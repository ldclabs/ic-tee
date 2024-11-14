use anyhow::Result;
use clap::Parser;
use structured_logger::{async_json::new_writer, get_env_level, Builder};
use tokio::io;

mod helper;
mod ip_to_vsock;
mod logtail;
mod vsock_to_ip_transparent;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// VSOCK address for outbound connections from enclave (e.g. 3:448)
    #[clap(long, default_value = "3:448")]
    outbound_vsock_addr: String,

    /// IP address to listen for inbound connections to enclave (e.g. 0.0.0.0:443)
    #[clap(long, default_value = "[::0]:443")]
    inbound_listen_addr: String,

    /// VSOCK address for inbound connections to enclave (e.g. 8:443)
    #[clap(long, default_value = "8:443")]
    inbound_vsock_addr: String,

    /// Address to listen for debug logs (e.g. 127.0.0.1:9999)
    #[arg(long, default_value = "127.0.0.1:9999")]
    logtail_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", new_writer(io::stdout()))
        .init();

    let serve_vsock_to_ip_transparent = async {
        let vsock_addr =
            helper::split_vsock(&cli.outbound_vsock_addr).map_err(anyhow::Error::msg)?;
        vsock_to_ip_transparent::serve(vsock_addr).await?;
        Ok(())
    };

    let serve_ip_to_vsock = async {
        let vsock_addr =
            helper::split_vsock(&cli.inbound_vsock_addr).map_err(anyhow::Error::msg)?;
        ip_to_vsock::serve(&cli.inbound_listen_addr, vsock_addr).await?;
        Ok(())
    };

    let serve_debug_log_addr = async {
        logtail::serve(&cli.logtail_addr).await?;
        Ok(())
    };

    match tokio::try_join!(
        serve_vsock_to_ip_transparent,
        serve_ip_to_vsock,
        serve_debug_log_addr
    ) {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: "server", "server error: {:?}", err);
            Err(err)
        }
    }
}
