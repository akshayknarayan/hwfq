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
}

use color_eyre::eyre::{bail, eyre, Report};
use etherparse::{TcpHeader, TransportHeader, UdpHeader};

fn get_ipv4_hdr(p: &etherparse::PacketHeaders<'_>) -> Result<etherparse::Ipv4Header, Report> {
    match p.net.as_ref().ok_or_else(|| eyre!("no ip header"))? {
        etherparse::NetHeaders::Ipv4(ipv4, _) => Ok(ipv4.clone()),
        x => {
            bail!("got {:?}", x);
        }
    }
}

fn get_dport(p: &etherparse::PacketHeaders<'_>) -> Result<u16, Report> {
    match p
        .transport
        .as_ref()
        .ok_or_else(|| eyre!("no transport header"))?
    {
        TransportHeader::Udp(UdpHeader {
            destination_port, ..
        })
        | TransportHeader::Tcp(TcpHeader {
            destination_port, ..
        }) => Ok(*destination_port),
        _ => {
            bail!("need UDP or TCP packet to get destination port");
        }
    }
}

impl TryFrom<Vec<u8>> for Pkt {
    type Error = (Vec<u8>, Report);

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        let parse_result = etherparse::PacketHeaders::from_ethernet_slice(&v)
            .map_err(Into::into)
            .and_then(|hdr| {
                let ip_hdr = get_ipv4_hdr(&hdr)?;
                let dport = get_dport(&hdr)?;
                Ok::<_, Report>((ip_hdr, dport))
            });
        match parse_result {
            Ok((ip_hdr, dport)) => {
                #[cfg(test)]
                let fake_len = v.len();
                Ok(Pkt {
                    ip_hdr,
                    dport,
                    buf: v,
                    #[cfg(test)]
                    fake_len,
                })
            }
            Err(e) => Err((v, e)),
        }
    }
}
