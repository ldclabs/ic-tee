use anyhow::{Context, Result};
use tokio::{
    io::copy_bidirectional_with_sizes,
    net::{TcpListener, TcpStream},
};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::helper::{ACCEPT_ERROR_DELAY, COPY_BUF_SIZE};

pub async fn serve(listen_addr: &str, server_addr: VsockAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .context("failed to bind listener")?;
    log::info!(target: "ip_to_vsock", "listening on {}, proxying to: {:?}", listen_addr, server_addr);

    loop {
        match listener.accept().await {
            Ok((inbound, _)) => {
                tokio::spawn(async move {
                    if let Err(err) = transfer(inbound, server_addr).await {
                        log::error!(target: "ip_to_vsock", "error in transfer: {:?}", err)
                    }
                });
            }
            Err(err) => {
                log::error!(target: "ip_to_vsock", "failed to accept connection: {:?}", err);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            }
        }
    }
}

async fn transfer(mut inbound: TcpStream, proxy_addr: VsockAddr) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?;
    inbound.set_nodelay(true)?;

    let mut outbound = VsockStream::connect(proxy_addr)
        .await
        .context("failed to connect vsock")?;

    copy_bidirectional_with_sizes(&mut inbound, &mut outbound, COPY_BUF_SIZE, COPY_BUF_SIZE)
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
