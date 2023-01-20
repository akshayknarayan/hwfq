use color_eyre::eyre::{ensure, Report, WrapErr};
use std::os::unix::net::UnixDatagram;
use structopt::StructOpt;
use tracing::debug;
use tun_tap::Iface;

#[derive(StructOpt, Debug)]
#[structopt(name = "uds_out")]
struct Opt {
    #[structopt(short, long, default_value = "hwfq-%d")]
    listen_interface: String,

    #[structopt(short, long)]
    packet_source: std::path::PathBuf,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();
    let opt = Opt::from_args();

    let iface = Iface::new(&opt.listen_interface, tun_tap::Mode::Tap)
        .wrap_err("could not create TAP interface")?;
    config_ip(iface.name())?;
    let sk = UnixDatagram::bind(&opt.packet_source).unwrap();

    fn msg(sk: &UnixDatagram, buf: &mut [u8], iface: &Iface) -> Result<(), Report> {
        let rlen = sk.recv(buf).wrap_err("uds recv")?;
        if let Ok(p) = etherparse::PacketHeaders::from_ethernet_slice(&buf[..rlen]) {
            tracing::trace!(?p.ip, "forwarding packet");
        }

        let msg = &mut buf[..rlen];
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
fn config_ip(name: &str) -> Result<(), Report> {
    ip_link_up(name)?;
    Ok(())
}

fn ip_link_up(dev: &str) -> Result<(), Report> {
    let status = Command::new("ip")
        .args(["link", "set", "up", "dev", dev])
        .status()?;
    ensure!(status.success(), "ip link up failed");
    Ok(())
}
