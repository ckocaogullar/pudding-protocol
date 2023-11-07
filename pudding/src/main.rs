use std::process::exit;
use std::time::Duration;

use clap::Parser;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber::filter::EnvFilter;

use pudding::orchestration::{GlobalConfiguration, Scenario, World};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of users
    #[arg(short = 'u', long, default_value_t = 1)]
    num_users: u32,

    /// Number of discovery servers
    #[arg(short = 's', long, default_value_t = 1)]
    num_servers: u32,

    /// Runtime in seconds
    #[arg(long, default_value_t = 20)]
    runtime_seconds: u32,

    /// Scenario to run (register or lookup)
    #[arg(long, default_value = "register")]
    scenario: String,

    /// Disables color (ANSI) output
    #[arg(long, default_value_t = false)]
    no_color: bool,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Setup logging
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_env_filter(EnvFilter::new("warn,pudding=debug"))
        .with_target(false)
        .with_file(true)
        .with_ansi(!args.no_color)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Tracing setup failed");

    let scenario = match args.scenario.as_str() {
        "register" => Scenario::Register,
        "lookup_identity" => Scenario::LookupIdentity,
        "lookup_anonymous" => Scenario::LookupAnonymous,
        x => panic!("unknown scenario option: {}", x),
    };
    info!(
        "Starting with u={} and s={} for scenario {:?} and will stop after {} seconds",
        args.num_users, args.num_servers, scenario, args.runtime_seconds
    );

    // Create world and play \o/
    let global_config = GlobalConfiguration::new(args.num_users, args.num_servers, scenario);
    let mut world = World::new(global_config);
    let runtime = Duration::from_secs(args.runtime_seconds as u64);

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let running = tokio::time::timeout(runtime, world.run());
    tokio::select! {
        _ = ctrl_c => {info!("Ctrl+C received"); exit(1)},
        _ = running => {info!("Runtime exceeded: will shutdown now"); exit(0)},
    }
}
