use clap::Parser;
use external_dns_desec_webhook::Config;

fn main() -> std::process::ExitCode {
    let config = Config::parse();

    if let Err(error) = run(&config) {
        eprintln!("error: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

fn run(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    config.validate()?;

    // Constructing the client is the whole point of --check-config: rustls loads the
    // system trust store here, not at first request, so an image without a CA bundle
    // fails at this line and nowhere earlier.
    let _client = desec::Client::builder()
        .token(config.token()?)
        .base_url(&config.api_url)
        .rate_limits(config.rate_limits()?)
        .build()?;

    if config.check_config {
        println!("configuration ok");
        return Ok(());
    }

    todo!("serve")
}
