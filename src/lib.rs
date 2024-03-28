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

    #[cfg(not(test))]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.fake_len
    }
}
