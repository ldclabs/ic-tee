use anyhow::Result;
use clap::Parser;
use tokio::{io, net::TcpListener};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(long, default_value = "127.0.0.1:9999")]
    ip_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let listener = TcpListener::bind(&cli.ip_addr).await?;
    println!("listening on {:?}", listener.local_addr()?);

    loop {
        match listener.accept().await {
            Err(err) => println!("couldn't get client: {:?}", err),
            Ok((mut stream, addr)) => {
                println!("accept a client: {:?}", addr);
                stream.readable().await?;
                io::copy(&mut stream, &mut io::stdout()).await?;
            }
        }
    }
}
