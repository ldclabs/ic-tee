use anyhow::{Context, Result};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};
use tokio_vsock::{VsockAddr, VsockStream};

pub async fn serve(listen_addr: &str, server_addr: VsockAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .context("failed to bind listener")?;
    log::info!(target: "ip_to_vsock", "listening on {}, proxying to: {:?}", listen_addr, server_addr);

    while let Ok((inbound, _)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(err) = transfer(inbound, server_addr).await {
                log::error!(target: "ip_to_vsock", "error in transfer: {:?}", err)
            }
        });
    }

    Err(anyhow::anyhow!("ip_to_vsock listener exited"))
}

async fn transfer(mut inbound: TcpStream, proxy_addr: VsockAddr) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?
        .to_string();

    let mut outbound = VsockStream::connect(proxy_addr)
        .await
        .context("failed to connect vsock")?;

    copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "error in connection between {} and {}, {:?}",
                inbound_addr,
                proxy_addr,
                err
            )
        })?;

    Ok(())
}
