//! Configuration, from flags or environment.
//!
//! Flags as well as environment variables, unlike the Go webhook this replaces, so
//! `--help` documents the surface and a typo in a name is an error rather than a silent
//! default. That mattered there: its README documented `WEBHOOK_ADDRESS` while its
//! envconfig read `WEBHOOK_WEBHOOKADDRESS`, so following the README left the server on
//! loopback and the operator with no clue why.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use desec::{Rate, RateLimits, Scope, Secret};

/// external-dns webhook provider for deSEC DNS.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Config {
    /// deSEC API token. Prefer --api-token-file in Kubernetes: an env var is visible in
    /// `kubectl describe pod` and inherited by anything the process spawns.
    #[arg(long, env = "DESEC_TOKEN", hide_env_values = true)]
    pub api_token: Option<String>,

    /// File to read the deSEC API token from, e.g. a mounted Secret.
    #[arg(long, env = "DESEC_TOKEN_FILE")]
    pub api_token_file: Option<PathBuf>,

    /// Zones to manage, comma-separated. Required: see `zones()`.
    #[arg(
        long,
        env = "DESEC_DOMAIN_FILTER",
        value_delimiter = ',',
        required = true
    )]
    pub domain_filter: Vec<String>,

    /// Zones to exclude from --domain-filter, comma-separated.
    #[arg(long, env = "DESEC_EXCLUDE_DOMAIN", value_delimiter = ',')]
    pub exclude_domain: Vec<String>,

    /// Base URL of the deSEC API.
    #[arg(long, env = "DESEC_API_URL", default_value = desec::DEFAULT_BASE_URL)]
    pub api_url: String,

    /// Address for the external-dns provider endpoints.
    ///
    /// Loopback by default and deliberately: these endpoints have no authentication, so
    /// binding them to the pod network exposes DNS write access to every pod that can
    /// reach it. The webhook is meant to run as a sidecar in external-dns's own pod.
    #[arg(long, env = "WEBHOOK_LISTEN", default_value = "127.0.0.1:8888")]
    pub listen: SocketAddr,

    /// Address for /healthz, /readyz and /metrics.
    #[arg(long, env = "WEBHOOK_ADMIN_LISTEN", default_value = "0.0.0.0:8080")]
    pub admin_listen: SocketAddr,

    /// How often to poll deSEC for zone changes.
    ///
    /// Not the same thing as external-dns's --interval: `/records` is served from cache,
    /// so the two are independent. Every tick costs one request against the account-wide
    /// 2000/day budget, which is why the default is not 60s — that alone would be 1440.
    #[arg(long, env = "WEBHOOK_REFRESH_INTERVAL", default_value = "180s", value_parser = humantime::parse_duration)]
    pub refresh_interval: Duration,

    /// Re-list a zone's records at least this often, even if deSEC says it is unchanged.
    ///
    /// A backstop against a bug in our own change detection, not against the API.
    #[arg(long, env = "WEBHOOK_MAX_ZONE_AGE", default_value = "6h", value_parser = humantime::parse_duration)]
    pub max_zone_age: Duration,

    /// Log the writes that would be made, without making them.
    #[arg(long, env = "WEBHOOK_DRY_RUN")]
    pub dry_run: bool,

    /// Serve an empty record set when no configured zone exists in the account.
    ///
    /// Off by default, because under `--policy=sync` an empty `/records` reply means
    /// "delete every record you own". Answering 503 instead keeps external-dns waiting
    /// rather than reconciling against a zone list we failed to load.
    #[arg(long, env = "WEBHOOK_ALLOW_EMPTY_ZONE_SET")]
    pub allow_empty_zone_set: bool,

    /// Label per-zone metrics with the zone name.
    #[arg(long, env = "WEBHOOK_METRICS_ZONE_LABELS")]
    pub metrics_zone_labels: bool,

    /// Largest request body accepted, in bytes.
    ///
    /// A big cluster's /adjustendpoints payload runs to tens of megabytes, so this is
    /// well above axum's 2 MiB default rather than at it.
    #[arg(long, env = "WEBHOOK_MAX_BODY_BYTES", default_value_t = 32 * 1024 * 1024)]
    pub max_body_bytes: usize,

    /// Override a deSEC rate-limit scope, as `scope=rate[,rate...]`, repeatable.
    ///
    /// For an account something else shares — cert-manager on the same token — where the
    /// documented rates are the account's budget rather than ours. Example:
    /// `--rate-limit dns_api_per_domain_expensive=1/s,7/min`.
    #[arg(long = "rate-limit", env = "WEBHOOK_RATE_LIMIT", value_delimiter = ';')]
    pub rate_limit: Vec<String>,

    /// Validate the configuration, construct the API client, and exit without making a
    /// request.
    ///
    /// Exists because rustls loads the system trust store when the client is
    /// constructed, so a container image without a CA bundle fails at startup while
    /// passing every test. This is what the image build checks.
    #[arg(long)]
    pub check_config: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no API token: pass --api-token or --api-token-file")]
    MissingToken,

    #[error("both --api-token and --api-token-file were given; pick one")]
    AmbiguousToken,

    #[error("could not read the API token from {path}")]
    UnreadableToken {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("--domain-filter is required, and must name at least one zone")]
    NoZones,

    #[error("--rate-limit {0:?} is not `scope=rate[,rate...]`")]
    MalformedRateLimit(String),

    #[error("--rate-limit names unknown scope {0:?}")]
    UnknownScope(String),

    #[error("--rate-limit {spec:?}: {source}")]
    MalformedRate {
        spec: String,
        #[source]
        source: desec::InvalidValue,
    },

    #[error("--max-zone-age must be at least --refresh-interval")]
    ZoneAgeBelowInterval,
}

impl Config {
    /// The token, from whichever source supplied it.
    pub fn token(&self) -> Result<Secret, ConfigError> {
        match (&self.api_token, &self.api_token_file) {
            (Some(_), Some(_)) => Err(ConfigError::AmbiguousToken),
            (Some(token), None) => Ok(Secret::from(token.clone())),
            (None, Some(path)) => std::fs::read_to_string(path)
                .map_err(|source| ConfigError::UnreadableToken {
                    path: path.clone(),
                    source,
                })
                // A Secret mounted from a file usually ends in a newline, and deSEC
                // answers 401 for a token with one.
                .map(|raw| Secret::from(raw.trim().to_owned())),
            (None, None) => Err(ConfigError::MissingToken),
        }
    }

    /// The zones we are willing to manage, normalized.
    ///
    /// Required, with no "manage everything" mode. external-dns under `--policy=sync`
    /// deletes any record in a managed zone it does not recognise, so an unfiltered
    /// webhook over a whole deSEC account is one misconfiguration away from erasing DNS
    /// the cluster never knew about.
    pub fn zones(&self) -> Result<Vec<String>, ConfigError> {
        let zones = normalize_names(&self.domain_filter);
        if zones.is_empty() {
            return Err(ConfigError::NoZones);
        }
        Ok(zones)
    }

    pub fn excluded_zones(&self) -> Vec<String> {
        normalize_names(&self.exclude_domain)
    }

    /// deSEC's documented rates, with any operator overrides applied.
    pub fn rate_limits(&self) -> Result<RateLimits, ConfigError> {
        let mut limits = RateLimits::desec_defaults();

        for spec in &self.rate_limit {
            let (scope, rates) = spec
                .split_once('=')
                .ok_or_else(|| ConfigError::MalformedRateLimit(spec.clone()))?;

            let scope = Scope::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == scope.trim())
                .ok_or_else(|| ConfigError::UnknownScope(scope.trim().to_owned()))?;

            let rates = rates
                .split(',')
                .map(str::trim)
                .filter(|rate| !rate.is_empty())
                .map(|rate| {
                    rate.parse::<Rate>()
                        .map_err(|source| ConfigError::MalformedRate {
                            spec: spec.clone(),
                            source,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;

            limits = limits.with_scope(scope, rates);
        }

        Ok(limits)
    }

    /// Cross-field checks, run once at startup so a bad combination fails loudly rather
    /// than behaving oddly for a day.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.token()?;
        self.zones()?;
        self.rate_limits()?;
        if self.max_zone_age < self.refresh_interval {
            return Err(ConfigError::ZoneAgeBelowInterval);
        }
        Ok(())
    }

    /// Requests per day the refresh loop will make when nothing is changing: one zone
    /// list per tick, plus each zone's periodic forced re-list.
    ///
    /// Reported at startup because the account-wide budget is 2000/day and the operator
    /// picked the interval without necessarily knowing that.
    pub fn estimated_daily_reads(&self, zone_count: u32) -> u64 {
        let per_day = |period: Duration| -> u64 {
            let secs = period.as_secs().max(1);
            86_400 / secs
        };
        per_day(self.refresh_interval) + u64::from(zone_count) * per_day(self.max_zone_age)
    }
}

/// Lowercase, strip a trailing dot, drop empties. Applied to every configured name so a
/// filter written `Example.COM.` matches what the API returns.
fn normalize_names(raw: &[String]) -> Vec<String> {
    let mut names: Vec<String> = raw
        .iter()
        .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &[&str]) -> Config {
        let mut argv = vec!["external-dns-desec-webhook"];
        argv.extend_from_slice(args);
        Config::try_parse_from(argv).expect("parses")
    }

    fn minimal() -> Config {
        config(&["--api-token", "t", "--domain-filter", "example.com"])
    }

    #[test]
    fn a_domain_filter_is_required() {
        assert!(
            Config::try_parse_from(["external-dns-desec-webhook", "--api-token", "t"]).is_err()
        );
    }

    #[test]
    fn zone_names_are_normalized() {
        let config = config(&[
            "--api-token",
            "t",
            "--domain-filter",
            "Example.COM.,  b.example.org  ,example.com",
        ]);
        assert_eq!(
            config.zones().expect("valid"),
            vec!["b.example.org", "example.com"]
        );
    }

    #[test]
    fn defaults_match_the_documented_deployment() {
        let config = minimal();
        assert_eq!(config.listen.to_string(), "127.0.0.1:8888");
        assert_eq!(config.admin_listen.to_string(), "0.0.0.0:8080");
        assert_eq!(config.refresh_interval, Duration::from_secs(180));
        assert!(!config.allow_empty_zone_set);
    }

    #[test]
    fn two_token_sources_is_an_error_rather_than_a_silent_preference() {
        let config = config(&[
            "--api-token",
            "t",
            "--api-token-file",
            "/nonexistent",
            "--domain-filter",
            "example.com",
        ]);
        assert!(matches!(config.token(), Err(ConfigError::AmbiguousToken)));
    }

    #[test]
    fn rate_limit_overrides_parse_desec_notation() {
        let config = config(&[
            "--api-token",
            "t",
            "--domain-filter",
            "example.com",
            "--rate-limit",
            "dns_api_per_domain_expensive=1/s,7/min",
        ]);
        let limits = config.rate_limits().expect("valid");
        assert_eq!(limits.rates(Scope::DnsApiPerDomainExpensive).len(), 2);
        // Untouched scopes keep deSEC's documented rates.
        assert_eq!(
            limits.rates(Scope::User),
            RateLimits::desec_defaults().rates(Scope::User)
        );
    }

    #[test]
    fn an_unknown_rate_limit_scope_is_rejected() {
        let config = config(&[
            "--api-token",
            "t",
            "--domain-filter",
            "example.com",
            "--rate-limit",
            "dns_api_free_lunch=1/s",
        ]);
        assert!(matches!(
            config.rate_limits(),
            Err(ConfigError::UnknownScope(_))
        ));
    }

    #[test]
    fn a_zone_age_below_the_refresh_interval_is_rejected() {
        let config = config(&[
            "--api-token",
            "t",
            "--domain-filter",
            "example.com",
            "--refresh-interval",
            "10m",
            "--max-zone-age",
            "1m",
        ]);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ZoneAgeBelowInterval)
        ));
    }

    /// The number that motivates the 180s default: at 60s the zone-list poll alone would
    /// be 1440/day against an account-wide budget of 2000.
    #[test]
    fn the_default_interval_leaves_room_in_the_daily_budget() {
        assert_eq!(minimal().estimated_daily_reads(20), 480 + 20 * 4);

        let hourly = config(&[
            "--api-token",
            "t",
            "--domain-filter",
            "example.com",
            "--refresh-interval",
            "60s",
        ]);
        assert_eq!(hourly.estimated_daily_reads(0), 1440);
    }
}
