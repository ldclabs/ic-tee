use anyhow::{Context, Result};
use tokio::{
    io::{copy_bidirectional_with_sizes, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::helper::{original_dst, ACCEPT_ERROR_DELAY, COPY_BUF_SIZE};

pub async fn serve(listen_addr: &str, proxy_addr: VsockAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .context("failed to bind listener")?;
    log::info!(target: "ip_to_vsock_transparent", "listening on {}, proxying to: {:?}", listen_addr, proxy_addr);

    loop {
        match listener.accept().await {
            Ok((inbound, _)) => {
                tokio::spawn(async move {
                    if let Err(err) = transfer(inbound, proxy_addr).await {
                        log::error!(target: "ip_to_vsock_transparent", "error in transfer: {:?}", err)
                    }
                });
            }
            Err(err) => {
                log::error!(target: "ip_to_vsock_transparent", "failed to accept connection: {:?}", err);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            }
        }
    }
}

async fn transfer(mut inbound: TcpStream, proxy_addr: VsockAddr) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?;
    let orig_dst = original_dst(&inbound).context("failed to retrieve original destination")?;
    log::info!(target: "ip_to_vsock_transparent", "original destination: {}", orig_dst);
    inbound.set_nodelay(true)?;

    let mut outbound = VsockStream::connect(proxy_addr)
        .await
        .context("failed to connect vsock")?;

    // send ip and port
    let mut header = [0u8; 6];
    header[..4].copy_from_slice(&u32::from(*orig_dst.ip()).to_le_bytes());
    header[4..].copy_from_slice(&orig_dst.port().to_le_bytes());
    outbound.write_all(&header).await?;

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
