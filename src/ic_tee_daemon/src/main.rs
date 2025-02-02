use anyhow::Result;
use clap::Parser;
use structured_logger::{async_json::new_writer, get_env_level, Builder};
use tokio::net::TcpStream;

mod helper;
mod ip_to_vsock_transparent;
mod vsock_to_ip;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// VSOCK address for outbound connections from enclave (e.g. 3:448)
    #[clap(long, default_value = "3:448")]
    outbound_vsock_addr: String,

    /// IP address to listen for outbound connections from enclave (e.g. 127.0.0.1:448)
    #[clap(long, default_value = "127.0.0.1:448")]
    outbound_listen_addr: String,

    /// VSOCK address for inbound connections to enclave (e.g. 8:443)
    #[clap(long, default_value = "8:443")]
    inbound_vsock_addr: String,

    /// IP address of listener in enclave (e.g. 127.0.0.1:8443)
    #[clap(long, default_value = "127.0.0.1:8443")]
    inbound_listen_addr: String,

    /// where the logtail server is running on host (e.g. 127.0.0.1:9999)
    #[arg(long, default_value = "127.0.0.1:9999")]
    logtail_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let writer = {
        let stream = TcpStream::connect(&cli.logtail_addr).await?;
        stream.writable().await?;
        new_writer(stream)
    };

    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", writer)
        .init();

    let serve_vsock_to_ip = async {
        let vsock_addr =
            helper::split_vsock(&cli.inbound_vsock_addr).map_err(anyhow::Error::msg)?;
        vsock_to_ip::serve(vsock_addr, &cli.inbound_listen_addr).await?;
        Ok(())
    };

    let serve_ip_to_vsock_transparent = async {
        let vsock_addr =
            helper::split_vsock(&cli.outbound_vsock_addr).map_err(anyhow::Error::msg)?;
        ip_to_vsock_transparent::serve(&cli.outbound_listen_addr, vsock_addr).await?;
        Ok(())
    };

    match tokio::try_join!(serve_vsock_to_ip, serve_ip_to_vsock_transparent) {
        Ok(_) => Ok(()),
        Err(err) => {
            log::error!(target: "server", "server error: {:?}", err);
            Err(err)
        }
    }
}
