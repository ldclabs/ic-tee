use anyhow::Result;
use clap::Parser;
use structured_logger::{async_json::new_writer, get_env_level, Builder};
use tokio::{io, net::TcpListener};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(long, default_value = "127.0.0.1:9999")]
    ip_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    let listener = TcpListener::bind(&cli.ip_addr).await?;
    log::info!(target: "logtail", "listening on {:?}", listener.local_addr()?);

    while let Ok((mut stream, addr)) = listener.accept().await {
        tokio::spawn(async move {
            log::info!(target: "logtail", "accept a client: {:?}", addr);
            let _ = stream.readable().await;
            if let Err(err) = io::copy(&mut stream, &mut io::stdout()).await {
                log::error!(target: "logtail", "error in transfer: {:?}", err);
            }
        });
    }
    Ok(())
}
