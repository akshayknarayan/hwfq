use color_eyre::eyre::{bail, eyre, Report, WrapErr};
use tracing::{debug, info, trace};

mod ip_socket;
pub use ip_socket::IpIfaceSocket;

pub mod scheduler;
use scheduler::Scheduler;

pub struct Datapath<S: Scheduler> {
    iface: IpIfaceSocket,
    out_port: OutputPort<S>,
}

impl<S: Scheduler + Send + 'static> Datapath<S> {
    pub fn new(
        in_iface: String,
        fwd_iface: String,
        tx_rate_bytes_per_sec: Option<usize>,
        sch: S,
    ) -> Result<Self, Report> {
        let iface = IpIfaceSocket::new(in_iface)?;
        let this = Self {
            iface,
            out_port: OutputPort::new(fwd_iface, tx_rate_bytes_per_sec, sch)?,
        };
        Ok(this)
    }

    pub fn run(self) -> Result<(), Report> {
        info!(iface=?self.iface.iface(), "starting");

        let fwd = self.out_port.start()?;
        let mut buf = [0u8; 2048];
        loop {
            let len = self.iface.recv(&mut buf)?;
            let recv_buf = &buf[0..len];
            let ip_hdr = match parse_and_get_ipv4_dst(recv_buf) {
                Ok(a) => a,
                Err(e) => {
                    debug!(err = %format!("{:#?}", e), "could not parse packet as ipv4");
                    continue;
                }
            };

            //let mut out_buf = &mut buf[4..len];
            //trace!(src = ?ip_hdr.source, dst = ?ip_hdr.destination, "queueing packet");
            //if let Err(e) = self.out_port.fwd.send(&mut out_buf, ip_hdr) {
            //    debug!(?e, "fwd error");
            //}

            // TODO route to output ports based on ip header?
            // currently we assume only 1.
            let out_buf = &buf[0..len];
            fwd.send(Pkt {
                ip_hdr,
                buf: out_buf.to_vec(),
            })
            .wrap_err("channel sending to scheduler")?;
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pkt {
    ip_hdr: etherparse::Ipv4Header,
    buf: Vec<u8>,
}

struct Rate {
    epoch_start: u64,
    bytes: usize,
}

struct OutputPort<S> {
    fwd: ip_socket::IpIfaceSocket,
    tx_rate_bytes_per_sec: Option<usize>,
    queue: S,
}

impl<S: Scheduler + Send + 'static> OutputPort<S> {
    fn new(
        out_iface: String,
        tx_rate_bytes_per_sec: Option<usize>,
        sch: S,
    ) -> Result<Self, Report> {
        let fwd = ip_socket::IpIfaceSocket::new(out_iface)?;
        Ok(Self {
            fwd,
            tx_rate_bytes_per_sec,
            queue: sch,
        })
    }

    fn start(self) -> Result<flume::Sender<Pkt>, Report> {
        let (s, r) = flume::unbounded();
        if let Some(tx_rate_bytes_per_sec) = self.tx_rate_bytes_per_sec {
            std::thread::spawn(move || self.run(r, tx_rate_bytes_per_sec));
        } else {
            std::thread::spawn(move || self.run_no_pacing(r));
        }
        Ok(s)
    }

    fn run_no_pacing(self, r: flume::Receiver<Pkt>) -> Result<(), Report> {
        info!("running with no pacing");
        let clk = quanta::Clock::new();
        let mut achieved_tx_rate: Option<Rate> = None;
        loop {
            let Pkt { ip_hdr, mut buf } = r.recv().unwrap();
            match &mut achieved_tx_rate {
                None => {
                    achieved_tx_rate = Some(Rate {
                        epoch_start: clk.raw(),
                        bytes: buf.len(),
                    });
                }
                Some(Rate { bytes, epoch_start }) => {
                    *bytes += buf.len();
                    let el = clk.delta(*epoch_start, clk.raw());
                    if el > std::time::Duration::from_millis(100) {
                        let epoch_rate_bytes_per_sec = *bytes as f64 / el.as_secs_f64();
                        let rate_mbps = epoch_rate_bytes_per_sec * 8. / 1e6;
                        info!(?rate_mbps, ?el, "achieved_tx_rate");
                        achieved_tx_rate = None;
                    }
                }
            }

            trace!(src = ?ip_hdr.source, dst = ?ip_hdr.destination, "forwarding packet");
            if let Err(e) = self.fwd.send(&mut buf, ip_hdr) {
                debug!(?e, "fwd error");
            }
        }
    }

    fn run(self, r: flume::Receiver<Pkt>, tx_rate_bytes_per_sec: usize) -> Result<(), Report> {
        // ticker
        // the bound here does not particularly matter. if we reach it, we will accumulate tokens
        // in token_bytes and tick over bigger token "blocks" in the next send.  it is the
        // receiver's responsibility to not have a quiet period cause a massive burst of packets.
        let (ticker_s, ticker_r) = flume::bounded(32);
        let tx_rate_bytes_per_usec = tx_rate_bytes_per_sec as f64 / 1e6;
        info!(?tx_rate_bytes_per_usec, "pacing");
        std::thread::spawn(move || {
            // try to send tokens for ~ 1500 bytes at a time.
            let clk = quanta::Clock::new();
            let mut token_bytes = 0;
            let mut then = clk.raw();
            loop {
                while token_bytes < 1500 {
                    // yield rather than sleep to prevent long sleeps.
                    // might need to replace yield_now with cpu_relax.
                    //std::thread::yield_now();
                    std::thread::sleep(std::time::Duration::from_micros(10));
                    let dur_us = clk.delta(then, clk.end()).as_micros() as f64;
                    then = clk.raw();
                    token_bytes += (dur_us * tx_rate_bytes_per_usec) as usize;
                }

                if let Ok(_) = ticker_s.try_send(token_bytes) {
                    token_bytes = 0;
                }
            }
        });

        let mut accum_tokens: isize = 0;
        let mut achieved_tx_rate: Option<Rate> = None;
        let clk = quanta::Clock::new();
        // both branches of the select can't happen at the same time, but the borrow checker
        // doesn't know that, and makes a fuss about queue being mutably borrowed twice.
        // So we are going to use RefCell.
        let queue = std::cell::RefCell::new(self.queue);
        loop {
            flume::select::Selector::new()
                .recv(&r, |p| {
                    let mut q = queue.try_borrow_mut().unwrap();
                    match q.enq(p.unwrap()) {
                    Ok(_) => {}
                    Err(e) => {
                        debug!(err=%format!("{:#?}", e), "enq error");
                    }
                }})
                .recv(&ticker_r, |bytes| {
                    let mut q = queue.try_borrow_mut().unwrap();
                    accum_tokens += bytes.unwrap() as isize;
                    while accum_tokens > 0 {
                        match q.deq() {
                            Ok(None) => {
                                if let Some(Rate { bytes, epoch_start }) = &achieved_tx_rate {
                                    let el = clk.delta(*epoch_start, clk.raw());
                                    if el > std::time::Duration::from_millis(10) {
                                        let epoch_rate_bytes_per_sec = *bytes as f64 / el.as_secs_f64();
                                        let rate_mbps = epoch_rate_bytes_per_sec * 8. / 1e6;
                                        debug!(?accum_tokens, ?rate_mbps, ?el, "queue_empty");
                                    }
                                }

                                // we're not active right now, so we get rid of any token backlog
                                // to avoid bursting. Once packets come back, we will resume
                                // building up a backlog.
                                achieved_tx_rate = None;
                                accum_tokens = 0;
                            }
                            Ok(Some(p)) => {
                                match &mut achieved_tx_rate {
                                    None => {
                                        achieved_tx_rate = Some(Rate {
                                            epoch_start: clk.raw(),
                                            bytes: p.buf.len(),
                                        });
                                    }
                                    Some(Rate { bytes, epoch_start }) => {
                                        *bytes += p.buf.len();
                                        let el = clk.delta(*epoch_start, clk.raw());
                                        if el > std::time::Duration::from_millis(100) {
                                            let epoch_rate_bytes_per_sec = *bytes as f64 / el.as_secs_f64();
                                            let rate_mbps = epoch_rate_bytes_per_sec * 8. / 1e6;
                                            info!(?rate_mbps, ?el, "achieved_tx_rate");
                                            achieved_tx_rate = None;
                                        }
                                    }
                                }

                                accum_tokens -= p.buf.len() as isize;
                                let Pkt { ip_hdr, mut buf } = p;
                                trace!(src = ?ip_hdr.source, dst = ?ip_hdr.destination, "forwarding packet");
                                if let Err(e) = self.fwd.send(&mut buf, ip_hdr) {
                                    debug!(?e, "fwd error");
                                }
                            }
                            Err(e) => {
                                debug!(?e, "deq error");
                            }
                        };
                    }
                }).wait();
        }
    }
}

fn parse_and_get_ipv4_dst(buf: &[u8]) -> Result<etherparse::Ipv4Header, Report> {
    let p = etherparse::PacketHeaders::from_ip_slice(buf)?;
    let ip_hdr = get_ipv4_hdr(p)?;
    Ok(ip_hdr)
}

fn get_ipv4_hdr<'a>(p: etherparse::PacketHeaders<'a>) -> Result<etherparse::Ipv4Header, Report> {
    match p.ip.ok_or_else(|| eyre!("no ip header"))? {
        etherparse::IpHeader::Version4(ipv4, _) => Ok(ipv4),
        x => {
            bail!("got {:?}", x);
        }
    }
}
