use color_eyre::eyre::{bail, ensure, eyre, Report, WrapErr};
use std::net::Ipv4Addr;
use std::process::Command;
use tun_tap::Iface;

mod ip_socket;
pub use ip_socket::IpIfaceSocket;

pub struct HwfqScheduler {
    iface: Iface,
    fwd: ip_socket::IpIfaceSocket,
}

impl HwfqScheduler {
    pub fn new(fwd_iface: String) -> Result<Self, Report> {
        let iface =
            Iface::new("hwfq-%d", tun_tap::Mode::Tun).wrap_err("could not create TUN interface")?;
        let fwd_sk = ip_socket::IpIfaceSocket::new(fwd_iface)?;
        let this = Self { iface, fwd: fwd_sk };
        this.config_ip()?;
        Ok(this)
    }

    fn config_ip(&self) -> Result<(), Report> {
        let name = self.iface.name();
        add_ip_addr(name, "100.64.0.1/24")?;
        ip_link_up(name)?;
        Ok(())
    }

    pub fn run(self) -> Result<(), Report> {
        let mut buf = [0u8; 2048];
        loop {
            let len = self.iface.recv(&mut buf)?;
            if len < 4 {
                println!("packet too small: {:?}", 4);
                continue;
            }

            let recv_buf = &buf[4..len];
            let dst_addr = match get_ipv4_dst(recv_buf) {
                Ok(a) => a,
                Err(e) => {
                    println!("err: {:#?}", e);
                    continue;
                }
            };

            println!("got: {:?}", recv_buf);

            // rewrite ip src addr
            let out_buf = &mut buf[4..len];
            out_buf[12..16].copy_from_slice(&[0u8; 4]);

            println!("sending to {:?}", dst_addr);
            self.fwd.send(out_buf)?;
        }
    }
}

fn get_ipv4_dst(buf: &[u8]) -> Result<Ipv4Addr, Report> {
    let p = etherparse::PacketHeaders::from_ip_slice(buf)?;
    let ip_hdr = get_ipv4_hdr(p)?;
    Ok(ip_hdr.destination.into())
}

fn add_ip_addr(dev: &str, ip_with_prefix: &str) -> Result<(), Report> {
    let status = Command::new("ip")
        .args(["addr", "add", "dev", dev, ip_with_prefix])
        .status()?;
    ensure!(status.success(), "ip addr add failed");
    Ok(())
}

fn ip_link_up(dev: &str) -> Result<(), Report> {
    let status = Command::new("ip")
        .args(["link", "set", "up", "dev", dev])
        .status()?;
    ensure!(status.success(), "ip addr add failed");
    Ok(())
}

fn get_ipv4_hdr<'a>(p: etherparse::PacketHeaders<'a>) -> Result<etherparse::Ipv4Header, Report> {
    match p.ip.ok_or_else(|| eyre!("no ip header"))? {
        etherparse::IpHeader::Version4(ipv4, _) => Ok(ipv4),
        _ => {
            bail!("only ipv4 supported");
        }
    }
}
