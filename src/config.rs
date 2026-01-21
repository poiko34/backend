use once_cell::sync::Lazy;
use std::env;
use flexi_logger::{Logger, FileSpec, Duplicate, Criterion, Naming, Cleanup};
use log::info;

pub static API_KEY: Lazy<String> = Lazy::new(|| {
    env::var("API_KEY").expect("API_KEY must be set")
});

pub fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    Logger::try_with_str("info")?
        .log_to_file(FileSpec::default().directory("logs").basename("api"))
        .duplicate_to_stderr(Duplicate::Warn)
        .rotate(Criterion::Size(1024 * 1024), Naming::Numbers, Cleanup::KeepLogFiles(5))
        .start()?;
    info!("Logger initialized");
    Ok(())
}