use color_eyre::eyre::{ensure, eyre, Report, WrapErr};
use etherparse::{Ipv4Header, TransportHeader};
use socket2::{Domain, Socket, Type};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;

/// Raw IP socekt bound to an interface (send only)
pub struct IpIfaceSocket {
    inner: Socket,
    bound_iface: String,
    bound_iface_src_ip: Ipv4Addr,
}

impl IpIfaceSocket {
    pub fn new(iface: String) -> Result<Self, Report> {
        let sk = Socket::new(Domain::IPV4, Type::RAW, Some(libc::IPPROTO_RAW.into()))
            .wrap_err("could not create raw ip socket")?;
        sk.set_header_included(true)
            .wrap_err("set header included sockopt")?;
        let iface_str_bytes = iface.as_bytes();
        ensure!(
            iface_str_bytes.len() <= libc::IFNAMSIZ,
            "interface name too long"
        );
        sk.bind_device(Some(iface_str_bytes))?;

        let bound_iface_src_ip = get_iface_ip(&iface)?;

        Ok(IpIfaceSocket {
            inner: sk,
            bound_iface: iface,
            bound_iface_src_ip,
        })
    }

    pub fn send(&self, buf: &mut [u8], mut ip_hdr: Ipv4Header) -> Result<(), Report> {
        let len = buf.len();

        // if the src ip addr is our own, clear it
        if ip_hdr.source == [100, 64, 0, 1] {
            ip_hdr.source = self.bound_iface_src_ip.octets();
            buf[12..16].copy_from_slice(&[0u8; 4]);
        }

        let p = etherparse::PacketHeaders::from_ip_slice(buf)?;
        let transp_hdr_start = ip_hdr.header_len();

        match p.transport {
            Some(TransportHeader::Udp(u)) => {
                // clear udp checksum
                let udp_hdr = &mut buf[transp_hdr_start..transp_hdr_start + u.header_len()];
                udp_hdr[6..8].copy_from_slice(&[0u8; 2]);
            }
            Some(TransportHeader::Tcp(tcp_hdr)) => {
                // calculate new tcp checksum
                let tcp_csum = tcp_hdr.calc_checksum_ipv4(&ip_hdr, p.payload)?;
                let tcp_hdr_buf =
                    &mut buf[transp_hdr_start..transp_hdr_start + tcp_hdr.header_len() as usize];
                tcp_hdr_buf[16..18].copy_from_slice(&tcp_csum.to_be_bytes());
            }
            None => (),
        }

        let s_addr = u32::from_be_bytes(self.bound_iface_src_ip.octets());
        let res = unsafe {
            let addr: libc::sockaddr = std::mem::transmute(libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_addr: libc::in_addr { s_addr },
                sin_port: 0,
                sin_zero: [0u8; 8],
            });

            libc::sendto(
                self.inner.as_raw_fd(),
                buf.as_ptr() as _,
                len,
                0,
                &addr as _,
                std::mem::size_of::<libc::sockaddr_in>() as _,
            )
        };

        ensure!(res > 0, "sendto failed");
        Ok(())
    }

    pub fn iface(&self) -> &str {
        &self.bound_iface
    }
}

fn get_iface_ip(iface: &str) -> Result<Ipv4Addr, Report> {
    let ifs = pnet::datalink::interfaces();
    let intf = ifs
        .iter()
        .find(|intf| &intf.name == iface)
        .ok_or_else(|| eyre!("Named interface not found"))?;
    let a = match intf
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| eyre!("Need ipv4 addr"))?
        .ip()
    {
        std::net::IpAddr::V4(a) => a,
        _ => unreachable!(),
    };

    Ok(a)
}
