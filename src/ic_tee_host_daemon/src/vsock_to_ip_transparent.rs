use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::{io::copy_bidirectional_with_sizes, io::AsyncReadExt, net::TcpStream};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use crate::helper::{ACCEPT_ERROR_DELAY, COPY_BUF_SIZE};

pub async fn serve(listen_addr: VsockAddr) -> Result<()> {
    let listener = VsockListener::bind(listen_addr).context("failed to bind listener")?;
    log::info!(target: "vsock_to_ip_transparent", "listening on {:?}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((inbound, _)) => {
                tokio::spawn(async move {
                    if let Err(err) = transfer(inbound).await {
                        log::error!(target: "vsock_to_ip_transparent", "error in transfer: {:?}", err)
                    };
                });
            }
            Err(err) => {
                log::error!(target: "vsock_to_ip_transparent", "failed to accept connection: {:?}", err);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            }
        }
    }
}

async fn transfer(mut inbound: VsockStream) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?;

    // read ip and port
    let proxy_addr = SocketAddr::new(
        IpAddr::V4(inbound.read_u32_le().await?.into()),
        inbound.read_u16_le().await?,
    );
    log::info!(target: "vsock_to_ip_transparent", "proxying to {:?}", proxy_addr);

    let mut outbound = TcpStream::connect(proxy_addr)
        .await
        .context("failed to connect to endpoint")?;
    outbound.set_nodelay(true)?;

    copy_bidirectional_with_sizes(&mut inbound, &mut outbound, COPY_BUF_SIZE, COPY_BUF_SIZE)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "error in connection between {:?} and {}, {:?}",
                inbound_addr,
                proxy_addr,
                err
            )
        })?;

    Ok(())
}
