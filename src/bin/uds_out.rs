use color_eyre::eyre::{ensure, Report, WrapErr};
use std::os::unix::net::UnixDatagram;
use structopt::StructOpt;
use tracing::debug;
use tun_tap::Iface;

#[derive(StructOpt, Debug)]
#[structopt(name = "uds_out")]
struct Opt {
    #[structopt(short, long)]
    packet_source: std::path::PathBuf,

    #[structopt(long)]
    ip: String,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();
    let opt = Opt::from_args();

    let iface =
        Iface::new("hwfq-%d", tun_tap::Mode::Tun).wrap_err("could not create TUN interface")?;
    config_ip(iface.name(), &opt.ip)?;
    let sk = UnixDatagram::bind(&opt.packet_source).unwrap();

    fn msg(sk: &UnixDatagram, buf: &mut [u8], iface: &Iface) -> Result<(), Report> {
        let rlen = sk.recv(buf).wrap_err("uds recv")?;
        let msg = &mut buf[..rlen];
        tracing::trace!(?msg, "got pkt");
        iface.send(msg)?;
        Ok(())
    }

    let mut buf = [0u8; 2048];
    loop {
        if let Err(e) = msg(&sk, &mut buf[..], &iface) {
            debug!(?e, "error");
        }
    }
}

use std::process::Command;
fn config_ip(name: &str, ip: &str) -> Result<(), Report> {
    add_ip_addr(name, &ip)?;
    ip_link_up(name)?;
    Ok(())
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
