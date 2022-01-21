use color_eyre::eyre::{bail, ensure, eyre, Report, WrapErr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, trace};
use tun_tap::Iface;

mod ip_socket;
pub use ip_socket::IpIfaceSocket;

mod scheduler;
use scheduler::Fifo;
pub use scheduler::Scheduler;

pub struct Datapath {
    iface: Iface,
    out_port: OutputPort,
}

impl Datapath {
    pub fn new(
        fwd_iface: String,
        tx_rate_bytes_per_sec: usize,
        qsize_bytes: usize,
    ) -> Result<Self, Report> {
        let iface =
            Iface::new("hwfq-%d", tun_tap::Mode::Tun).wrap_err("could not create TUN interface")?;
        let this = Self {
            iface,
            out_port: OutputPort::new(fwd_iface, tx_rate_bytes_per_sec, qsize_bytes)?,
        };
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
        info!(iface=?self.iface.name(), "starting");

        let fwd = self.out_port.start()?;
        let mut buf = [0u8; 2048];
        loop {
            let len = self.iface.recv(&mut buf)?;
            if len < 4 {
                debug!(?len, "packet too small");
                continue;
            }

            let recv_buf = &buf[4..len];
            let ip_hdr = match parse_and_get_ipv4_dst(recv_buf) {
                Ok(a) => a,
                Err(e) => {
                    debug!(?e, "could not parse packet as ipv4");
                    continue;
                }
            };

            // TODO route to output ports based on ip header?
            // currently we assume only 1.
            trace!(src = ?ip_hdr.source, dst = ?ip_hdr.destination, "queueing packet");
            let out_buf = &buf[4..len];
            fwd.send(Pkt {
                ip_hdr,
                buf: out_buf.to_vec(),
            })
            .wrap_err("channel sending to scheduler")?;
        }
    }
}

pub struct Pkt {
    ip_hdr: etherparse::Ipv4Header,
    buf: Vec<u8>,
}

struct OutputPort {
    tx_rate_bytes_per_sec: usize,
    queue: Arc<Mutex<Fifo>>,
    fwd: ip_socket::IpIfaceSocket,
}

impl OutputPort {
    fn new(
        out_iface: String,
        tx_rate_bytes_per_sec: usize,
        qsize_bytes: usize,
    ) -> Result<Self, Report> {
        let fwd = ip_socket::IpIfaceSocket::new(out_iface)?;
        Ok(Self {
            fwd,
            tx_rate_bytes_per_sec,
            queue: Arc::new(Mutex::new(Fifo::new(qsize_bytes))),
        })
    }

    fn start(self) -> Result<flume::Sender<Pkt>, Report> {
        let (s, r) = flume::bounded(128);
        std::thread::spawn(move || self.run(r));
        Ok(s)
    }

    fn run(self, r: flume::Receiver<Pkt>) -> Result<(), Report> {
        let (active_s, active_r) = flume::bounded(1);

        info!("starting output port");

        // enq
        let q = Arc::clone(&self.queue);
        std::thread::spawn(move || loop {
            trace!("wait for incoming packet");
            let p = r.recv().unwrap();
            trace!("got incoming packet");
            match {
                let mut g = q.lock().unwrap();
                g.enq(p)
            } {
                Ok(true) => {
                    trace!("wake up deq");
                    active_s.try_send(()).unwrap_or(());
                }
                Ok(false) => {}
                Err(e) => {
                    debug!(?e, "enq error");
                }
            }
        });

        let clk = quanta::Clock::new();

        // deq
        // we can assume that packets will mostly be ~ the same size.
        let q = self.queue;
        let tx_rate_bytes_per_usec = self.tx_rate_bytes_per_sec as f64 / 1e6;
        let mut deficit_bytes = 0;
        loop {
            let p: Pkt = match {
                let mut g = q.lock().unwrap();
                g.deq()
            } {
                Ok(Some(p)) => p,
                Ok(None) => {
                    // wait for this queue to become active.
                    trace!("wait for enq");
                    active_r.recv().unwrap();
                    trace!("woke up");
                    continue;
                }
                Err(e) => {
                    debug!(?e, "error on dequeue");
                    continue;
                }
            };

            // timer loop: wait until we can send this packet.
            //
            // yield rather than sleep to prevent long sleeps.
            // might need to replace yield_now with cpu_relax.
            while deficit_bytes < p.buf.len() {
                let then = clk.start();
                std::thread::yield_now();
                let now = clk.end();
                let dur_us = clk.delta(then, now).as_micros() as f64;
                deficit_bytes += (dur_us * tx_rate_bytes_per_usec) as usize;
            }

            // now we can send the packet.
            deficit_bytes -= p.buf.len();
            let Pkt { ip_hdr, mut buf } = p;
            trace!(src = ?ip_hdr.source, dst = ?ip_hdr.destination, "forwarding packet");

            self.fwd.send(&mut buf, ip_hdr)?;
        }
    }
}

fn parse_and_get_ipv4_dst(buf: &[u8]) -> Result<etherparse::Ipv4Header, Report> {
    let p = etherparse::PacketHeaders::from_ip_slice(buf)?;
    let ip_hdr = get_ipv4_hdr(p)?;
    Ok(ip_hdr)
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
