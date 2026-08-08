use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use external_dns_desec_webhook::{
    Config, admin, apply::Applier, client, config::ConfigError, metrics::Metrics,
    refresh::Refresher, router, store::SnapshotStore, wire::DomainFilter,
};

/// How long in-flight requests get to finish after a shutdown signal.
///
/// Matched to external-dns's own client budget: past that, no request still in flight can
/// usefully complete, and holding the pod in Terminating serves nobody.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("could not construct the deSEC client")]
    Client(#[source] desec::Error),
    #[error("could not bind {address}")]
    Bind {
        address: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("server failed")]
    Serve(#[source] std::io::Error),
}

fn main() -> std::process::ExitCode {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("external_dns_desec_webhook=info,warn")
            }),
        )
        .init();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: could not start the async runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(config)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "startup failed");
            eprintln!("error: {error}");
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<(), StartupError> {
    config.validate()?;
    let zones = config.zones()?;
    let excluded = config.excluded_zones();

    // The tuning lives in `client`, which is also what `--check-config` exercises.
    let client = client::build(config.token()?, &config.api_url, config.rate_limits()?)
        .map_err(StartupError::Client)?;

    if config.check_config {
        println!("configuration ok");
        return Ok(());
    }

    if !config.listen.ip().is_loopback() {
        tracing::warn!(
            address = %config.listen,
            "the provider endpoints have no authentication; binding them off loopback grants \
             DNS write access to anything that can reach this port. Run as a sidecar in \
             external-dns's own pod instead."
        );
    }

    let estimated = config.estimated_daily_reads(u32::try_from(zones.len()).unwrap_or(u32::MAX));
    tracing::info!(
        zones = ?zones,
        refresh_interval_s = config.refresh_interval.as_secs(),
        "starting; {}",
        Metrics::describe_budget(estimated)
    );
    if estimated > 1000 {
        tracing::warn!(
            estimated,
            "this configuration spends more than half of deSEC's 2000/day account budget on \
             polling alone; consider a longer --refresh-interval"
        );
    }

    let store = SnapshotStore::new();
    let metrics = Arc::new(Metrics::new(
        config.metrics_zone_labels,
        env!("CARGO_PKG_VERSION"),
    ));

    let refresher = Refresher::new(
        client.clone(),
        store.clone(),
        Arc::clone(&metrics),
        zones.clone(),
        excluded.clone(),
        config.refresh_interval,
        config.max_zone_age,
    );
    let liveness = refresher.liveness();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let refresh_task = tokio::spawn(refresher.run(shutdown_rx));

    let provider = router::router(router::AppState {
        store: store.clone(),
        applier: Arc::new(Applier::new(client, store.clone(), config.dry_run)),
        metrics: Arc::clone(&metrics),
        // The filter external-dns is told about comes from configuration, not from the API,
        // so the handshake cannot fail because deSEC is unreachable. It happens once at
        // external-dns's startup and failing it is fatal there.
        filter: DomainFilter {
            include: zones,
            exclude: excluded,
            ..DomainFilter::default()
        },
        allow_empty_zone_set: config.allow_empty_zone_set,
        max_body_bytes: config.max_body_bytes,
    });

    let admin = admin::router(admin::AdminState {
        store,
        metrics,
        liveness,
        refresh_interval: config.refresh_interval,
    });

    let provider_listener = bind(config.listen).await?;
    let admin_listener = bind(config.admin_listen).await?;
    tracing::info!(provider = %config.listen, admin = %config.admin_listen, "listening");

    let mut provider_shutdown = shutdown_tx.subscribe();
    let mut admin_shutdown = shutdown_tx.subscribe();

    let servers = async {
        tokio::try_join!(
            axum::serve(provider_listener, provider).with_graceful_shutdown(async move {
                let _ = provider_shutdown.changed().await;
            }),
            axum::serve(admin_listener, admin).with_graceful_shutdown(async move {
                let _ = admin_shutdown.changed().await;
            }),
        )
        .map(|_| ())
    };

    tokio::select! {
        result = servers => result.map_err(StartupError::Serve)?,
        () = terminate() => {
            tracing::info!("shutting down");
            let _ = shutdown_tx.send(true);
            // Bounded: a drain that waits indefinitely holds the pod in Terminating for
            // longer than any request could still usefully take.
            if tokio::time::timeout(SHUTDOWN_GRACE, refresh_task).await.is_err() {
                tracing::warn!("refresh task did not stop within the grace period");
            }
        }
    }

    Ok(())
}

async fn bind(address: std::net::SocketAddr) -> Result<tokio::net::TcpListener, StartupError> {
    tokio::net::TcpListener::bind(address)
        .await
        .map_err(|source| StartupError::Bind { address, source })
}

/// Resolves on `SIGINT` or `SIGTERM`. Kubernetes sends the latter.
async fn terminate() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let sigterm = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {}
        () = sigterm => {}
    }
}
