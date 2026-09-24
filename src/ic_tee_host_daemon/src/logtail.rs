use anyhow::{Context, Result};
use tokio::{io, net::TcpListener};

use crate::helper::ACCEPT_ERROR_DELAY;

pub async fn serve(listen_addr: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .context("failed to bind listener")?;
    log::info!(target: "logtail", "listening on {:?}", listener.local_addr()?);

    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                tokio::spawn(async move {
                    log::info!(target: "logtail", "accept a client: {:?}", addr);
                    if let Err(err) = io::copy(&mut stream, &mut io::stdout()).await {
                        log::error!(target: "logtail", "error in transfer: {:?}", err);
                    }
                });
            }
            Err(err) => {
                log::error!(target: "logtail", "failed to accept connection: {:?}", err);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            }
        }
    }
}
