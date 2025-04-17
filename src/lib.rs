use std::fmt::Display;

use color_eyre::eyre::{bail, eyre, Report};
use etherparse::{Ipv4Header, TcpHeader, TransportHeader, UdpHeader};

pub mod scheduler;
pub use scheduler::Scheduler;

#[cfg(feature = "datapath")]
mod datapath;
#[cfg(feature = "datapath")]
pub use datapath::Datapath;

#[cfg(all(target_os = "linux", feature = "datapath"))]
mod ip_socket;
#[cfg(all(target_os = "linux", feature = "datapath"))]
pub use ip_socket::IpIfaceSocket;

#[derive(Debug)]
pub enum Error {
    PacketDropped(Pkt),
    Other(Report),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketDropped(Pkt { ip_hdr, dport, .. }) => f.write_fmt(format_args!(
                "Dropping packet: {}.{}.{}.{} -> {}.{}.{}.{}:{}",
                ip_hdr.source[0],
                ip_hdr.source[1],
                ip_hdr.source[2],
                ip_hdr.source[3],
                ip_hdr.destination[0],
                ip_hdr.destination[1],
                ip_hdr.destination[2],
                ip_hdr.destination[3],
                dport,
            )),
            Self::Other(r) => f.write_fmt(format_args!("{}", r)),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PacketDropped(_) => None,
            Self::Other(r) => Some(r.as_ref()),
        }
    }
}

/// A packet buffer.
///
/// This type is only exposed so that [`Scheduler`] implementations have something to store. The
/// raw fields are deliberately not exposed. Instead we provide read-access to the header
/// ([`Pkt::hdr`]) and to the packet's length ([`Pkt::len`]).
///
/// # Implementation Details
/// The buffer `buf` includes the header, but we also store the parsed IPv4 header in `ip_hdr` for
/// convenience.
#[derive(Clone, Debug)]
pub struct Pkt {
    ip_hdr: etherparse::Ipv4Header,
    sport: u16,
    dport: u16,
    buf: Vec<u8>,
    #[cfg(test)]
    fake_len: usize,
}

impl Pkt {
    pub fn hdr(&self) -> &etherparse::Ipv4Header {
        &self.ip_hdr
    }

    pub fn dport(&self) -> u16 {
        self.dport
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf
    }
    pub fn buf_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    #[cfg(not(test))]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[cfg(not(test))]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.fake_len
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.fake_len == 0
    }

    fn from_packet_headers(
        parse_result: Result<(Ipv4Header, u16, u16), Report>,
        v: Vec<u8>,
    ) -> Result<Self, (Vec<u8>, Report)> {
        match parse_result {
            Ok((ip_hdr, sport, dport)) => {
                #[cfg(test)]
                let fake_len = v.len();
                Ok(Pkt {
                    ip_hdr,
                    sport,
                    dport,
                    buf: v,
                    #[cfg(test)]
                    fake_len,
                })
            }
            Err(e) => Err((v, e)),
        }
    }

    pub fn parse_ethernet(v: Vec<u8>) -> Result<Self, (Vec<u8>, Report)> {
        Self::from_packet_headers(
            etherparse::PacketHeaders::from_ethernet_slice(&v)
                .map_err(Into::into)
                .and_then(|hdr| {
                    let ip_hdr = get_ipv4_hdr(&hdr)?;
                    let (sport, dport) = get_ports(&hdr)?;
                    Ok::<_, Report>((ip_hdr, sport, dport))
                }),
            v,
        )
    }

    pub fn parse_ip(v: Vec<u8>) -> Result<Self, (Vec<u8>, Report)> {
        Self::from_packet_headers(
            etherparse::PacketHeaders::from_ip_slice(&v)
                .map_err(Into::into)
                .and_then(|hdr| {
                    let ip_hdr = get_ipv4_hdr(&hdr)?;
                    let (sport, dport) = get_ports(&hdr)?;
                    Ok::<_, Report>((ip_hdr, sport, dport))
                }),
            v,
        )
    }
}

fn get_ipv4_hdr(p: &etherparse::PacketHeaders<'_>) -> Result<etherparse::Ipv4Header, Report> {
    match p.net.as_ref().ok_or_else(|| eyre!("no ip header"))? {
        etherparse::NetHeaders::Ipv4(ipv4, _) => Ok(ipv4.clone()),
        x => {
            bail!("got {:?}", x);
        }
    }
}

fn get_ports(p: &etherparse::PacketHeaders<'_>) -> Result<(u16, u16), Report> {
    match p
        .transport
        .as_ref()
        .ok_or_else(|| eyre!("no transport header"))?
    {
        TransportHeader::Udp(UdpHeader {
            source_port,
            destination_port,
            ..
        })
        | TransportHeader::Tcp(TcpHeader {
            source_port,
            destination_port,
            ..
        }) => Ok((*source_port, *destination_port)),
        _ => {
            bail!("need UDP or TCP packet to get destination port");
        }
    }
}

#[cfg(test)]
mod test_util {
    pub fn make_pkt(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: Option<u16>,
        dport: Option<u16>,
        len: usize,
    ) -> crate::Pkt {
        crate::Pkt {
            ip_hdr: etherparse::Ipv4Header::new(100, 64, etherparse::IpNumber::TCP, src_ip, dst_ip)
                .unwrap(),
            sport: sport.unwrap_or(0),
            dport: dport.unwrap_or(0),
            buf: vec![],
            fake_len: len,
        }
    }
}
