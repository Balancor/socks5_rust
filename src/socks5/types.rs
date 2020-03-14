
use nom::number::complete::{le_u8, be_u16, be_u32};
use std::str::from_utf8;

use byteorder::{WriteBytesExt, BigEndian};
use std::net::{SocketAddr, Ipv4Addr, IpAddr, Ipv6Addr};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum AuthMethod {
    NoAuth,
    GSSAPI,
    UserNamePassword,
    IANAAssigned,
    Reserved,
    NoAcceptedMethod
}

named!(pub parser_auth_method<AuthMethod>,
    do_parse!(
        method :switch!(le_u8,
            0x00    => value!(AuthMethod::NoAuth)           |
            0x01    => value!(AuthMethod::GSSAPI)           |
            0x02    => value!(AuthMethod::UserNamePassword) |
            0x03    => value!(AuthMethod::IANAAssigned)     |
            0x80    => value!(AuthMethod::Reserved)         |
            0xFF    => value!(AuthMethod::NoAcceptedMethod))    >>
        (method)
    )
);


pub fn auth_method_to_byte(autho_method :AuthMethod) -> u8 {
    let method_u8 = match autho_method {
        AuthMethod::NoAuth              => 0x00,
        AuthMethod::GSSAPI              => 0x01,
        AuthMethod::UserNamePassword    => 0x02,
        AuthMethod::IANAAssigned        => 0x03,
        AuthMethod::Reserved            => 0x80,
        AuthMethod::NoAcceptedMethod    => 0xFF,
    };
    method_u8
}

named!(pub parser_auth_methods<Vec<AuthMethod>>,
    many0!(parser_auth_method));
#[test]
fn test_parser_auth_methods() {
    let buf  = vec![0x00, 0x02, 0x03, 0x01];
    let (_, methods) = parser_auth_methods(buf.as_ref()).unwrap();

    println!("Request: {:#?}", methods);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequire {
    pub version :u8,
    pub num_method :u8,
    pub methods :Vec<AuthMethod>
}

named!(pub parser_auth_require<AuthRequire>,
    do_parse!(
        version :le_u8                  >>
        number_method: le_u8            >>
        methods :many_m_n!(0, number_method as usize, parser_auth_method) >>
        (AuthRequire{
            version: version,
            num_method: number_method,
            methods: methods.to_owned(),
        })
    )
);

impl AuthRequire {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes :Vec<u8> = Vec::new();

        raw_bytes.push(self.version);
        raw_bytes.push(self.num_method);

        for i in 0..self.num_method {
            raw_bytes.push(auth_method_to_byte(self.methods[i as usize]));
        }
        raw_bytes
    }
}

#[test]
fn test_parser_auth_require() {
    let buf  = vec![0x05, 0x02, 0x00, 0x01];
    let (_, request) = parser_auth_require(buf.as_ref()).unwrap();

    println!("Request: {:#?}", request);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthResponse {
    pub version :u8,
    pub choosed_method :AuthMethod,
}

named!(pub parser_auth_response<AuthResponse>,
    do_parse!(
        version :le_u8                  >>
        choosed_method :parser_auth_method  >>
        (AuthResponse{
            version,
            choosed_method,
        })
    )
);

impl AuthResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes :Vec<u8> = Vec::new();

        raw_bytes.push(self.version);
        raw_bytes.push(auth_method_to_byte(self.choosed_method));

        raw_bytes
    }
}

#[derive(Clone,Debug,PartialEq,Eq)]
pub enum SocksAddress {
    Ipv4(u32, u16),
    Domain(String, u16),
    Ipv6(Vec<u16>, u16),
}

impl SocksAddress {
    fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes:Vec<u8> = Vec::new();

        match self {
            SocksAddress::Ipv4(val, port) => {
                raw_bytes.push(0x01);
                let mut wtr = vec![];
                wtr.write_u32::<BigEndian>(*val).unwrap();
                raw_bytes.extend(wtr);

                let mut wtr = vec![];
                wtr.write_u16::<BigEndian>(port.clone()).unwrap();
                raw_bytes.extend(wtr);
            }

            SocksAddress::Domain(domain, port) => {
                raw_bytes.push(0x03);
                let len = domain.len() as u8;
                raw_bytes.push(len);
                raw_bytes.extend(domain.as_bytes());

                let mut wtr = vec![];
                wtr.write_u16::<BigEndian>(port.clone()).unwrap();
                raw_bytes.extend(wtr);
            }

            SocksAddress::Ipv6(val, port) => {
                raw_bytes.push(0x04);
                for v in val {
                    raw_bytes.push((v & 0x0f) as u8);
                    raw_bytes.push(((v >> 8) & 0x0f) as u8);
                }

                let mut wtr = vec![];
                wtr.write_u16::<BigEndian>(port.clone()).unwrap();
                raw_bytes.extend(wtr);
            }
        }

        raw_bytes
    }

    fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
        use std::net::ToSocketAddrs;

        let addrs = (host, port).to_socket_addrs().unwrap();
        for addr in addrs {
            if let SocketAddr::V4(_) = addr {
                return addr;
            }
        }
        unreachable!("Cannot lookup address");
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
           SocksAddress::Ipv4(val, port) => {
               let ipv4addr =Ipv4Addr::new((val >> 24) as u8, (val >> 16)  as u8,
                                           (val >> 8) as u8, (val & 0xFF) as u8);
               Some(SocketAddr::new(IpAddr::V4(ipv4addr), port.clone()))
           },
           SocksAddress::Domain(val, port) => {
               Some(SocksAddress::lookup_ipv4(&val, port.clone()))
           },
           SocksAddress::Ipv6(val, port) => {
               Some(SocketAddr::new(IpAddr::V6(
                   Ipv6Addr::new(val[0], val[1],val[2], val[3],
                                 val[4], val[5],val[6], val[7] )), port.clone()))
           },
       }
    }
}

named!(pub parser_addr_ipv4<SocksAddress>,
    do_parse!(
        ipv4: be_u32       >>
        port: be_u16       >>
        (SocksAddress::Ipv4(ipv4, port))
    )
);

#[test]
fn test_parser_ipv4_address(){
    let ipv4_addr:Vec<u8> = vec![220, 181, 38, 148, 1, 187];

    let (_, address) = parser_addr_ipv4(ipv4_addr.as_slice()).unwrap();

    println!("address: {:#?}", address);

}

named!(pub parser_domain<&str>, map_res!(length_data!(le_u8), from_utf8));
named!(pub parser_addr_domain<SocksAddress>,
    do_parse!(
        domain :parser_domain   >>
        port: be_u16       >>
        (SocksAddress::Domain(String::from(domain), port))
    ));

named!(pub parser_addr_ipv6<SocksAddress>,
    do_parse!(
        ipv6 :many_m_n!(0, 8, be_u16)   >>
        port: be_u16       >>
        (SocksAddress::Ipv6(ipv6.to_owned(), port))
    ));

named!(pub parser_socks_address<SocksAddress>,
    do_parse!(
        address: switch!(le_u8,
            0x01    => call!(parser_addr_ipv4)   |
            0x03    => call!(parser_addr_domain) |
            0x04    => call!(parser_addr_ipv6))  >>
        (address)
    )
);

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum SocksCommand {
    CmdTcp,
    CmdBind,
    CmdUdp
}

impl SocksCommand {
    fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes:Vec<u8> = Vec::new();

        match self {
            SocksCommand::CmdTcp => {
                raw_bytes.push(0x01 as u8);
            },
            SocksCommand::CmdBind => {
                raw_bytes.push(0x02 as u8);
            },
            SocksCommand::CmdUdp => {
                raw_bytes.push(0x03 as u8);
            },
        };
        raw_bytes
    }
}

named!(pub parser_socks_command<SocksCommand>,
    do_parse!(
        cmd :switch!(le_u8,
            0x01    => value!(SocksCommand::CmdTcp)  |
            0x02    => value!(SocksCommand::CmdBind) |
            0x03    => value!(SocksCommand::CmdUdp)) >>
        (cmd)
    )
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectRequire {
    pub version :u8,
    pub command :SocksCommand,
    pub reserved :u8,
    pub dest_address :SocksAddress,
}

impl ConnectRequire {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.push(self.version);
        raw_bytes.extend(self.command.to_bytes());
        raw_bytes.push(self.reserved);
        raw_bytes.extend(self.dest_address.to_bytes());

        raw_bytes
    }
}



named!(pub parser_connect_require<ConnectRequire>,
    do_parse!(
        version: le_u8                      >>
        command: parser_socks_command       >>
        reserved: le_u8                     >>
        dest_address: parser_socks_address  >>
        (ConnectRequire{
            version,
            command,
            reserved,
            dest_address
        })
    )
);


#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ConnectStatus {
    ConnectSuccess,
    GenSocksServerFailed,
    ConnectDeny,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupport,
    AddressTypeNotSupport,
    Unassigned,
}

impl ConnectStatus {
    fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        let stat = match self {
            ConnectStatus::ConnectSuccess           => { 0x00 as u8 },
            ConnectStatus::GenSocksServerFailed     => { 0x01 as u8 },
            ConnectStatus::ConnectDeny              => { 0x02 as u8 },
            ConnectStatus::NetworkUnreachable       => { 0x03 as u8 },
            ConnectStatus::HostUnreachable          => { 0x04 as u8 },
            ConnectStatus::ConnectionRefused        => { 0x05 as u8 },
            ConnectStatus::TTLExpired               => { 0x06 as u8 },
            ConnectStatus::CommandNotSupport        => { 0x07 as u8 },
            ConnectStatus::AddressTypeNotSupport    => { 0x08 as u8 },
            ConnectStatus::Unassigned               => { 0x09 as u8 },
        };

        raw_bytes.push(stat);
        raw_bytes
    }
}

named!(pub parser_connect_status<ConnectStatus>,
    do_parse!(
        status :switch!(le_u8,
            0x00    => value!(ConnectStatus::ConnectSuccess)        |
            0x01    => value!(ConnectStatus::GenSocksServerFailed)  |
            0x02    => value!(ConnectStatus::ConnectDeny)           |
            0x03    => value!(ConnectStatus::NetworkUnreachable)    |
            0x04    => value!(ConnectStatus::HostUnreachable)       |
            0x05    => value!(ConnectStatus::ConnectionRefused)     |
            0x06    => value!(ConnectStatus::TTLExpired)            |
            0x07    => value!(ConnectStatus::CommandNotSupport)     |
            0x08    => value!(ConnectStatus::AddressTypeNotSupport) |
            0x09    => value!(ConnectStatus::Unassigned))   >>
        (status)
    )
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectResponse {
    pub version :u8,
    pub status :ConnectStatus,
    pub reserved :u8,
    pub bind_address :SocksAddress,
}

impl ConnectResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.push(self.version);
        raw_bytes.extend(self.status.to_bytes());
        raw_bytes.push(self.reserved);
        raw_bytes.extend(self.bind_address.to_bytes());

        raw_bytes
    }
}

named!(pub parser_connect_response<ConnectResponse>,
    do_parse!(
        version :le_u8                      >>
        status :parser_connect_status                       >>
        reserved :le_u8                     >>
        bind_address :parser_socks_address  >>
        bind_port :be_u16                   >>
        (ConnectResponse {
            version,
            status,
            reserved,
            bind_address
        })
    )
);


