use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::{io::copy_bidirectional_with_sizes, net::TcpStream};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use crate::helper::{ACCEPT_ERROR_DELAY, COPY_BUF_SIZE};

pub async fn serve(listen_addr: VsockAddr, server_addr: &str) -> Result<()> {
    let listener = VsockListener::bind(listen_addr).context("failed to bind listener")?;
    let addr: SocketAddr = server_addr
        .parse()
        .context("failed to parse server address")?;
    log::info!(target: "vsock_to_ip", "listening on {:?}, proxying to {:?}", listen_addr, addr);

    loop {
        match listener.accept().await {
            Ok((inbound, _)) => {
                tokio::spawn(async move {
                    if let Err(err) = transfer(inbound, addr).await {
                        log::error!(target: "vsock_to_ip", "error in transfer: {:?}", err)
                    };
                });
            }
            Err(err) => {
                log::error!(target: "vsock_to_ip", "failed to accept connection: {:?}", err);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            }
        }
    }
}

async fn transfer(mut inbound: VsockStream, server_addr: SocketAddr) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?;

    log::info!(target: "vsock_to_ip", "proxying to {:?}", server_addr);

    let mut outbound = TcpStream::connect(server_addr)
        .await
        .context("failed to connect to endpoint")?;
    outbound.set_nodelay(true)?;

    copy_bidirectional_with_sizes(&mut inbound, &mut outbound, COPY_BUF_SIZE, COPY_BUF_SIZE)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "error in connection between {:?} and {}, {:?}",
                inbound_addr,
                server_addr,
                err
            )
        })?;

    Ok(())
}
