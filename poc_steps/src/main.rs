use poc_steps::{config::PocStepsConfig, setup, withdrawal};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing()?;

    let config = PocStepsConfig::default();
    println!(
        "\nBoomerang regime starts at block:     {}",
        config.boomerang.milestone_block_0
    );
    println!(
        "Withdrawal starts at block:           {}",
        config
            .withdrawal
            .absolute_locktime_for_withdrawal_transaction
    );
    println!(
        "Boomerang regime finishes at block:   {}\n",
        config.boomerang.milestone_block_1
    );
    let boomerang_entities = setup::run(&config.boomerang)?;
    withdrawal::run(boomerang_entities, &config.boomerang, &config.withdrawal).await?;

    Ok(())
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}
