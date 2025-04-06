use crate::net::{IOEventHandler, IOProcessor, IO};
use log::info;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;

mod net;
mod quic;

fn build_sock() -> socket2::Socket {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    [
        (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1u32),
        (libc::IPPROTO_UDP, libc::UDP_GRO, 1u32),
    ]
    .into_iter()
    .for_each(|(proto, opt, val)| unsafe {
        let r = libc::setsockopt(
            sock.as_raw_fd(),
            proto,
            opt,
            &raw const val as *const _,
            std::mem::size_of_val(&val) as u32,
        );
        if r < 0 {
            log::warn!("setsockopt failed: {}", r);
        } else {
            log::warn!("setsockopt success: {}", r);
        }
    });
    sock.set_only_v6(false).unwrap();
    sock
}

struct TestHandler {}

impl IOEventHandler for TestHandler {
    fn handle_recvmsg(&self, to: net::Fixed, from: std::net::SocketAddrV6, buf: &[u8]) {
        // log::info!("Received message from {} to {:?}", from, to);
    }
}

const STUNMSG: [u8; 20] = [
    0x00, 0x01, // STUN message type (Binding Request)
    0x00, 0x00, // Message length (0 for no attributes)
    0x21, 0x12, 0xA4, 0x42, // Magic cookie (fixed value)
    0xAA, 0xDD, 0x00, 0x33, // Transaction ID (part 1)
    0xBB, 0xEE, 0x11, 0x44, // Transaction ID (part 2)
    0xCC, 0xFF, 0x22, 0x55, // Transaction ID (part 3)
];
fn run_all() {
    info!("Begin");
    let mut io = net::IOLoop::new();
    info!("build_sock");
    let sock = build_sock();
    info!("register_fd");
    let sock_id = io.register_fd(sock.as_raw_fd()).unwrap();

    let stun_addr: SocketAddrV6 = "[::ffff:74.125.250.129]:19302".parse().unwrap();
    io.op_recv_multishot(sock_id);

    IOProcessor::from(&mut io).sendmsg(sock_id, stun_addr, STUNMSG.as_slice().into());

    let mut handler = TestHandler {};

    info!("Running loop");
    io.run_loop(&mut handler);
}

mod test {
    use super::*;

    #[test]
    fn test_run_all() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
        run_all();
    }
}
