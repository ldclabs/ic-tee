use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::{io::copy_bidirectional, io::AsyncReadExt, net::TcpStream};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

pub async fn serve(listen_addr: VsockAddr) -> Result<()> {
    let mut listener = VsockListener::bind(listen_addr).expect("failed to bind listener");
    log::info!(target: "vsock_to_ip_transparent", "listening on {:?}", listen_addr);

    while let Ok((inbound, _)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(err) = transfer(inbound).await {
                log::error!(target: "vsock_to_ip_transparent", "error in transfer: {:?}", err)
            };
        });
    }

    Err(anyhow::anyhow!("vsock_to_ip_transparent listener exited"))
}

async fn transfer(mut inbound: VsockStream) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?
        .to_string();

    // read ip and port
    let proxy_addr = SocketAddr::new(
        IpAddr::V4(inbound.read_u32_le().await?.into()),
        inbound.read_u16_le().await?,
    );
    log::info!(target: "vsock_to_ip_transparent", "proxying to {:?}", proxy_addr);

    let mut outbound = TcpStream::connect(proxy_addr)
        .await
        .context("failed to connect to endpoint")?;

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
