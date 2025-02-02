use anyhow::{Context, Result};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::helper::AddrInfo;

pub async fn serve(listen_addr: &str, server_addr: VsockAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .context("failed to bind listener")?;
    log::info!(target: "ip_to_vsock_transparent", "listening on {}, proxying to: {:?}", listen_addr, server_addr);

    while let Ok((inbound, _)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(err) = transfer(inbound, server_addr).await {
                log::error!(target: "ip_to_vsock_transparent", "error in transfer: {:?}", err)
            }
        });
    }

    Err(anyhow::anyhow!("ip_to_vsock_transparent listener exited"))
}

async fn transfer(mut inbound: TcpStream, proxy_addr: VsockAddr) -> Result<()> {
    let inbound_addr = inbound
        .peer_addr()
        .context("could not fetch inbound addr")?
        .to_string();

    let orig_dst = inbound
        .get_original_dst()
        .ok_or(anyhow::anyhow!("Failed to retrieve original destination"))?;
    log::info!(target: "vsock_to_ip_transparent", "Original destination: {}", orig_dst);

    let mut outbound = VsockStream::connect(proxy_addr)
        .await
        .context("failed to connect vsock")?;

    // send ip and port
    let v4 = if let std::net::SocketAddr::V4(v4) = orig_dst {
        *v4.ip()
    } else {
        return Err(anyhow::anyhow!("Received ipv6 address"));
    };
    outbound.write_u32_le(v4.into()).await?;
    outbound.write_u16_le(orig_dst.port()).await?;

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
