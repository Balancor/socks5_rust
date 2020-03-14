use std::net::{SocketAddr};
use crate::socks5::types::*;

use std::error::Error;

use tokio::io;
use tokio::net::TcpStream;
use tokio::prelude::*;

use futures::future::try_join;


#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum SessionState {
    SocksInitialize,
    SocksAuthed,
    SocksRefused,
    SocksTimeout,
    SocksConnectedRemote,
}

#[derive(Debug)]
pub struct Session {
    pub client_addr :SocketAddr,
    pub socks_server_socket :TcpStream,
    pub proxy_server_socket :Option<TcpStream>,
    pub session_state :SessionState,
}

impl Session {
    pub fn new( stream :TcpStream, addr :SocketAddr) -> Session {
        Session {
            client_addr: addr,
            socks_server_socket: stream,
            proxy_server_socket: None,
            session_state: SessionState::SocksInitialize
        }
    }

    async fn proxy(&mut self)->Result<(), Box<dyn Error>>{
        let proxy_stream = self.proxy_server_socket.as_mut().unwrap();

        let (mut ri, mut wi) = self.socks_server_socket.split();
        let (mut ro, mut wo) = proxy_stream.split();

        let client_to_server = io::copy(&mut ri, &mut wo);
        let server_to_client = io::copy(&mut ro, &mut wi);

        try_join(client_to_server, server_to_client).await?;

        Ok(())
    }


    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        self.handle_auth().await?;
        self.handle_connection().await?;

        self.proxy().await?;

        Ok(())
    }

    async fn read_length(stream :&mut TcpStream, length :u8) -> Vec<u8> {
        let mut raw_bytes = vec![0; length as usize];
        let mut read_sum = 0;

        loop {
            let read_length = stream.read(&mut raw_bytes[read_sum as usize..]).await.unwrap();
            read_sum += read_length;
            if read_sum == length as usize {
                break;
            } else if read_sum > length as usize {
                unreachable!("Should not read the length of data more than {}", length);
            }
        }

        raw_bytes.to_vec()
    }

    async fn read_u8(stream :&mut TcpStream) -> u8 {
        let raw_bytes = Session::read_length(stream, 1).await;
        raw_bytes[0]
    }

    pub async fn read_negotiation_auth_require(&mut self) -> Result<AuthRequire, Box<dyn Error>> {
        let stream = &mut self.socks_server_socket;

        let version = Session::read_u8(stream).await;
        let num_method = Session::read_u8(stream).await;
        let raw_methods = Session::read_length(stream, num_method).await;
        let (_, methods) = parser_auth_methods(raw_methods.as_ref()).unwrap();

        Ok(AuthRequire{
            version,
            num_method,
            methods
        })
    }

    async fn handle_auth(&mut self) -> Result<(), Box<dyn Error>> {
        let mut auth_response = AuthResponse {
            version: 0x05,
            choosed_method: AuthMethod::NoAuth,
        };

        let auth_request = self.read_negotiation_auth_require().await.unwrap();
        for i in 0..auth_request.num_method {
            if AuthMethod::NoAuth == auth_request.methods[i as usize] {
                auth_response.choosed_method = AuthMethod::NoAuth;
                break;
            }
        }

        self.socks_server_socket.write(auth_response.to_bytes().as_ref())
            .await.expect("failed to write data to socket");
        Ok(())
    }

    async fn handle_connection(&mut self) -> Result<(), Box<dyn Error>> {
        let mut connect_response = ConnectResponse {
            version: 0x05,
            status: ConnectStatus::ConnectSuccess,
            reserved: 0,
            bind_address: SocksAddress::Ipv4(0, 0),
        };

        let connect_request = self.read_connection_require().await.unwrap();
        let proxy_server_address = connect_request.dest_address.to_socket_addr().unwrap();
        match connect_request.command {
            SocksCommand::CmdTcp => {
                match TcpStream::connect(&proxy_server_address).await {
                    Result::Ok(val) => {
                        self.proxy_server_socket = Some(val);
                        connect_response.bind_address = connect_request.dest_address.clone();
                        connect_response.status = ConnectStatus::ConnectSuccess;
                    },
                    Result::Err(err) => {
                        println!("Error: {}", err);
                        connect_response.status = ConnectStatus::NetworkUnreachable;
                    }
                }
            },
            SocksCommand::CmdBind => {},
            SocksCommand::CmdUdp => {},
        }

        self.socks_server_socket.write(connect_response.to_bytes().as_ref()).await
            .expect("failed to write data to socket");

        Ok(())
    }

    async fn read_connection_require(&mut self) -> Result<ConnectRequire, Box<dyn Error>> {
        let mut stream = &mut self.socks_server_socket;

        let version = Session::read_u8(&mut stream).await;
        let cmd_byte = Session::read_u8(&mut stream).await;
        let reserved = Session::read_u8(&mut stream).await;
        let address_type = Session::read_u8(&mut stream).await;

        let mut raw_address_bytes = Vec::new();
        raw_address_bytes.push(address_type);
        match address_type {
            0x01 => {
                let address_bytes = Session::read_length(stream,6).await;
                raw_address_bytes.extend(address_bytes);
            },
            0x03 => {
                let length = stream.read_u8().await.unwrap();
                let domain_bytes = Session::read_length(stream, length  + 2).await;

                raw_address_bytes.push(length);
                raw_address_bytes.extend(domain_bytes);
            },
            0x04 => {
                let address_bytes = Session::read_length(stream, 18).await;
                raw_address_bytes.extend(address_bytes);
            },
            _ => { }
        };

        let (_, command) = parser_socks_command(vec![cmd_byte].as_slice()).unwrap();
        let (_, dest_address) = parser_socks_address(raw_address_bytes.as_ref()).unwrap();

        Ok(ConnectRequire{
            version,
            command,
            reserved,
            dest_address,
        })
    }

}