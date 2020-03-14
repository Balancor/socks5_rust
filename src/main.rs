#[macro_use]
extern crate nom;
extern crate tokio;

mod socks5;
use crate::socks5::session::*;

use std::error::Error;
use tokio::net::TcpListener;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = "127.0.0.1:1080".to_string();
    let mut listener = TcpListener::bind(&address).await?;
    while let Ok((socket, client_addr)) = listener.accept().await {
        tokio::spawn(async move {
            let mut client = Session::new(socket, client_addr);
            client.start().await;
        });
    }
    Ok(())
}