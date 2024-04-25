# Userspace Packet Scheduling in Rust

`hwfq` contains userspace implementations of a few useful scheduling algorithms, as well as a datapath to run them in userspace via a TUN/TAP interface.

## Schedulers

Schedulers implement the `Scheduler` trait, and can be used anywhere this trait is the right interface. This crate is currently opinionated about what a packet is, and specifically targets packets that parse as TCP/IP or UDP/IP.

## Datapath module

The datapath module will capture packets on a TUN interface, apply rate limiting to simulate a link (bring your own delay emulation), apply scheduler implementations, and then forward packets out over a Unix pipe. The `uds_out` process can read from this pipe and send packets out via a second TUN interface. 
