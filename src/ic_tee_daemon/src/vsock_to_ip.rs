use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::{io::copy_bidirectional, net::TcpStream};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

pub async fn serve(listen_addr: VsockAddr, server_addr: &str) -> Result<()> {
    let listener = VsockListener::bind(listen_addr).expect("failed to bind listener");
    let addr: SocketAddr = server_addr
        .parse()
        .context("failed to parse server address")?;
    log::info!(target: "vsock_to_ip", "listening on {:?}, proxying to {:?}", listen_addr, addr);

    while let Ok((inbound, _)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(err) = transfer(inbound, addr).await {
                log::error!(target: "vsock_to_ip", "error in transfer: {:?}", err)
            };
        });
    }

    Err(anyhow::anyhow!("vsock_to_ip listener exited"))
}

async fn transfer(mut inbound: VsockStream, server_addr: SocketAddr) -> Result<()> {
    let inbound_addr = inbound
        .local_addr()
        .context("could not fetch inbound addr")?
        .to_string();

    log::info!(target: "vsock_to_ip", "proxying to {:?}", server_addr);

    let mut outbound = TcpStream::connect(server_addr)
        .await
        .context("failed to connect to endpoint")?;

    copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "error in connection between {} and {}, {:?}",
                inbound_addr,
                server_addr,
                err
            )
        })?;

    Ok(())
}
