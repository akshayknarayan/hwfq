use color_eyre::eyre::{ensure, eyre, Report, WrapErr};
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

    pub fn send(&self, buf: &[u8]) -> Result<(), Report> {
        let len = buf.len();
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
