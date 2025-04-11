//! Paced user-space TUN/TAP-based packet scheduler.
//!
//! This crate implements user-space packet scheduling via a TUN/TAP device. The primary motivation
//! is to provide an implementation of Hierarchical Deficit Weighted Round Robin, which is in
//! [`scheduler::HierarchicalDeficitWeightedRoundRobin`].
//!
//! To achieve this, we need:
//! - A packet pacer, which accepts a pacing rate. We thus emulate a zero-latency link with the
//! given pacing rate. The implementation uses a token-bucket-style approach.
//! - A scheduler ([`scheduler::Scheduler`]), which schedules the resulting queue.
//!
//! The entry point for this functionality is [`Datapath`]. Packets flow into the TUN/TAP device
//! that [`Datapath`] manages, and it forwards packets to a named Unix pipe. This pipe must exist
//! and handle packets; if it does not exist, [`Datapath::new`] will error, but if it black-holes
//! packets [`Datapath`] will not complain.

use color_eyre::eyre::{ensure, Report, WrapErr};
use flume::RecvError;
use std::process::Command;
use std::time::SystemTime;
use tracing::{debug, info, trace};
use tun_tap::Iface;

use crate::scheduler::Scheduler;
use crate::{get_ipv4_hdr, get_ports, Pkt};

/// Manage pacing, scheduling (via the parameter), and forwarding packets to a Unix pipe.
///
/// We use a TAP device, and we only queue IPv4 packets. Other packets bypass the queue and go
/// straight to the Unix pipe.
pub struct Datapath<S: Scheduler> {
    iface: Iface,
    out_port: OutputPort<S>,
}

impl<S: Scheduler + Send + 'static> Datapath<S> {
    /// Initialize the TAP device using the interface name `listen_iface`.
    /// We will forward packets to the Unix pipe at `fwd_iface`, and pace packets at the rate
    /// `tx_rate_bytes_per_sec`. If `tx_rate_bytes_per_sec` is `None`, we will not apply pacing and
    /// simply forward packets. Note that in most cases, this will make the scheduling useless
    /// because there will be no queue to schedule. The scheduler `sch` should implement the
    /// [`Scheduler`] trait.
    pub fn new(
        listen_iface: &str,
        fwd_iface: &str,
        tx_rate_bytes_per_sec: Option<usize>,
        sch: S,
    ) -> Result<Self, Report> {
        let iface = Iface::new(listen_iface, tun_tap::Mode::Tap)
            .wrap_err("could not create TAP interface")?;
        let this = Self {
            iface,
            out_port: OutputPort::new(fwd_iface, tx_rate_bytes_per_sec, sch)?,
        };
        this.config_ip()?;
        Ok(this)
    }

    fn config_ip(&self) -> Result<(), Report> {
        let name = self.iface.name();
        ip_link_up(name)?;
        Ok(())
    }

    /// Start the datapath.
    #[tracing::instrument(level = "info", skip(self), err)]
    pub fn run(self) -> Result<(), Report> {
        info!(iface=?self.iface.name(), "starting");

        let bypass = self.out_port.get_bypass()?;
        let fwd = self.out_port.start()?;
        let mut buf = [0u8; 2048];
        loop {
            let len = self.iface.recv(&mut buf)?;
            if len < 4 {
                debug!(?len, "packet too small");
                continue;
            }

            let recv_buf = &buf[4..len];
            let hdr = match etherparse::PacketHeaders::from_ethernet_slice(recv_buf) {
                Ok(h) => h,
                Err(e) => {
                    trace!(err = %format!("{:#?}", e), "could not parse packet");
                    if let Err(err) = bypass.send(&buf) {
                        debug!(?err, "error sending packet via bypass");
                    }

                    continue;
                }
            };

            let ip_hdr = match get_ipv4_hdr(&hdr) {
                Ok(ip_hdr) => ip_hdr,
                Err(e) => {
                    trace!(err = %format!("{:#?}", e), "could not parse packet as ipv4");
                    if let Err(err) = bypass.send(&buf) {
                        debug!(?err, "error sending non-ipv4 packet via bypass");
                    }

                    continue;
                }
            };

            let (sport, dport) = match get_ports(&hdr) {
                Ok(p) => p,
                Err(e) => {
                    trace!(err = %format!("{:#?}", e), "could not parse packet as ipv4");
                    if let Err(err) = bypass.send(&buf) {
                        debug!(?err, "error sending non-ipv4 packet via bypass");
                    }

                    continue;
                }
            };

            // TODO route to output ports based on ip header?
            // currently we assume only 1.
            let out_buf = &buf[0..len];
            fwd.send(Pkt {
                ip_hdr,
                sport,
                dport,
                buf: out_buf.to_vec(),
                #[cfg(test)]
                fake_len: 0,
            })
            .wrap_err("channel sending to scheduler")?;
        }
    }
}

struct Rate {
    epoch_start: u64,
    bytes: usize,
}

struct OutputPort<S> {
    fwd: std::os::unix::net::UnixDatagram,
    tx_rate_bytes_per_sec: Option<usize>,
    queue: S,
}

impl<S: Scheduler + Send + 'static> OutputPort<S> {
    fn new(out_iface: &str, tx_rate_bytes_per_sec: Option<usize>, sch: S) -> Result<Self, Report> {
        let fwd = std::os::unix::net::UnixDatagram::unbound().unwrap();
        fwd.connect(out_iface).unwrap();
        Ok(Self {
            fwd,
            tx_rate_bytes_per_sec,
            queue: sch,
        })
    }

    fn get_bypass(&self) -> Result<std::os::unix::net::UnixDatagram, Report> {
        self.fwd.try_clone().wrap_err("try cloning unix socket")
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

    #[tracing::instrument(level = "info", skip(self, r), err)]
    fn run_no_pacing(self, r: flume::Receiver<Pkt>) -> Result<(), Report> {
        info!("running with no pacing");
        let clk = quanta::Clock::new();
        let mut achieved_tx_rate: Option<Rate> = None;
        loop {
            let Pkt { ip_hdr, buf, .. } = r.recv().unwrap();
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
            if let Err(e) = self.fwd.send(&buf) {
                debug!(?e, "fwd error");
            }
        }
    }

    #[tracing::instrument(level = "info", skip(self, r), err)]
    fn run(self, r: flume::Receiver<Pkt>, tx_rate_bytes_per_sec: usize) -> Result<(), Report> {
        // ticker
        // the bound here does not particularly matter. if we reach it, we will accumulate tokens
        // in token_bytes and tick over bigger token "blocks" in the next send.  it is the
        // receiver's responsibility to not have a quiet period cause a massive burst of packets.
        let (ticker_s, ticker_r) = flume::bounded(32);
        let tx_rate_bytes_per_usec = tx_rate_bytes_per_sec as f64 / 1e6;
        info!(?tx_rate_bytes_per_sec, "pacing");
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
                    let dur_us = clk.delta(then, clk.raw()).as_micros() as f64;
                    then = clk.raw();
                    token_bytes += (dur_us * tx_rate_bytes_per_usec) as usize;
                }

                if ticker_s.try_send(token_bytes).is_ok() {
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

        let handle_incoming = |p: Result<Pkt, RecvError>| {
            let mut q = queue.try_borrow_mut().unwrap();
            match q.enq(p.unwrap()) {
                Ok(_) => {}
                Err(e) => {
                    debug!(err=%format!("{:#?}", e), "enq error");
                }
            }
        };

        let mut need_dequeue = false;

        loop {
            if !need_dequeue {
                let p = r.recv();
                handle_incoming(p);
                need_dequeue = true;
            } else {
                flume::select::Selector::new()
                    .recv(&r, handle_incoming)
                    .recv(&ticker_r, |bytes| {
                        let mut q = queue.try_borrow_mut().unwrap();
                        accum_tokens += bytes.unwrap() as isize;
                        debug!(
                            "Accumtokenupdate Time: {:?}, accum_tokens: {}",
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs_f64(),
                            accum_tokens
                        );
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
                                    need_dequeue = false;
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
                                                let achieved_rate_mbps = epoch_rate_bytes_per_sec * 8. / 1e6;
                                                info!(?achieved_rate_mbps, ?el, "pacing update");
                                                achieved_tx_rate = None;
                                                q.dbg(el);
                                            }
                                        }
                                    }

                                    accum_tokens -= p.buf.len() as isize;
                                    let Pkt { ip_hdr, buf, .. } = p;
                                    debug!(src = ?ip_hdr.source, dst = ?ip_hdr.destination, "forwarding packet");
                                    if let Err(e) = self.fwd.send(&buf) {
                                        debug!(?e, "fwd error");
                                    }
                                }
                                Err(e) => {
                                    debug!(?e, "deq error");
                                }
                            };
                        }
                })
                .wait();
            }
        }
    }
}

fn ip_link_up(dev: &str) -> Result<(), Report> {
    let status = Command::new("ip")
        .args(["link", "set", "up", "dev", dev])
        .status()?;
    ensure!(status.success(), "ip link set up failed");
    Ok(())
}
