use anyhow::Result;
use tokio::{io, net::TcpListener};

pub async fn serve(listen_addr: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .expect("failed to bind listener");
    log::info!(target: "logtail", "listening on {:?}", listener.local_addr()?);

    while let Ok((mut stream, addr)) = listener.accept().await {
        tokio::spawn(async move {
            log::info!(target: "logtail", "accept a client: {:?}", addr);
            let _ = stream.readable().await;
            if let Err(err) = io::copy(&mut stream, &mut io::stdout()).await {
                log::error!(target: "logtail", "error in transfer: {:?}", err);
            }
        });
    }

    Err(anyhow::anyhow!("logtail listener exited"))
}
