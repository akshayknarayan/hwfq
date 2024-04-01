use clap::Parser;
use color_eyre::eyre::{ensure, Report, WrapErr};
use std::os::unix::net::UnixDatagram;
use tracing::debug;
use tun_tap::Iface;

#[derive(Parser, Debug)]
#[command(name = "uds_out")]
struct Opt {
    #[arg(short, long, default_value = "hwfq-%d")]
    listen_interface: String,

    #[arg(short, long)]
    packet_source: std::path::PathBuf,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();
    let opt = Opt::parse();

    let iface = Iface::new(&opt.listen_interface, tun_tap::Mode::Tun)
        .wrap_err("could not create TUN interface")?;
    config_ip(iface.name())?;
    let sk = UnixDatagram::bind(&opt.packet_source).unwrap();

    fn msg(sk: &UnixDatagram, buf: &mut [u8], iface: &Iface) -> Result<(), Report> {
        let rlen = sk.recv(buf).wrap_err("uds recv")?;
        match etherparse::PacketHeaders::from_ip_slice(&buf[..rlen]) {
            Ok(p) => tracing::trace!(?p.net, "forwarding packet"),
            Err(err) => tracing::trace!(?err, "forwarding parse failed"),
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
