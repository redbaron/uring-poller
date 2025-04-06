use super::buf_ring::BufRing;
use crate::net::stats::Stats;
use crate::net::{stats, IOEventHandler, TimerKey, TimerUserData};
use bitvec::prelude::*;
use bytes::Bytes;
use io_uring::cqueue;
use io_uring::squeue::{Entry, Flags};
use io_uring::types::{Fd, Fixed, RecvMsgOut, Timespec};
use io_uring::{opcode, IoUring, SubmissionQueue};
use libc::sockaddr_storage;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::SocketAddrV6;
use std::time::Duration;

// MUST be power of 2;
const MAX_EVENTS: usize = 8192;

// We use GSO, that is multiple datagrams received by network card are
// coaelsced into large buffer by the kernel or even hardware.
// There is a balance to strike: if sender sends just small number of packets
// whole buffer is wasted. On the other hand if we don't do GSO then there is a
// recvmsg per packet which is more expensive.
const RECVBUF_SIZE: usize = 16384;

const NUM_FIXED_FILES: usize = 32;

pub(crate) enum Op {
    SendMsg(SendMsgOp),
    RecvMsgMulti(RecvMsgMultiOp),
    Timer(TimerOp),
}

pub(crate) struct SendMsgOp {
    fixed: Fixed,
    addr: socket2::SockAddr,
    buf: Bytes,

    // When creating SendMsg opcode we need to pass raw pointers to these structs. These are were we store them.
    iov: MaybeUninit<libc::iovec>,
    msghdr: MaybeUninit<libc::msghdr>,
}

pub(crate) struct RecvMsgMultiOp {
    fixed: Fixed,
    bgid: u16,

    // When creating SendMsg opcode we need to pass raw pointers to these structs. These are were we store them.
    msghdr: libc::msghdr,
}

impl RecvMsgMultiOp {
    fn build(&mut self) -> Entry {
        self.msghdr = new_msghdr();
        let msghdr = &mut self.msghdr;

        // multishot msghdr is more like a blueprint for future msghdrs
        // len arguments here specify how much of resulting buffer will
        // be taken to store values in real msghdr
        msghdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        msghdr.msg_controllen = (size_of::<libc::cmsghdr>() + size_of::<u16>()) /* UDP_GRO */ as _;
        opcode::RecvMsgMulti::new(self.fixed, msghdr as *const _, self.bgid).build()
    }
}

pub(crate) struct TimerOp {
    pub timer_key: TimerKey,
    // When creating Timer opcode we need to pass raw pointers to these structs. These are were we store them.
    // When None: remove timer
    pub timespec: Option<Timespec>,
    pub is_update: bool,
}

impl TimerOp {
    fn opcode(&self) -> u8 {
        if self.timespec.is_none() {
            opcode::TimeoutRemove::CODE
        } else if self.is_update {
            opcode::TimeoutUpdate::CODE
        } else {
            opcode::Timeout::CODE
        }
    }
}

fn new_msghdr() -> libc::msghdr {
    // SAFETY: all zeros is a valid state for POD structs
    unsafe { MaybeUninit::zeroed().assume_init() }
}

// Our CQE user_data(u64) mapping
// | timers_userdata<u32> = 32bits | reserved | opcode<u8> = 8 bits | OpKey: log2(MAX_EVENTS) = 13 bits |
// OpKey is an index in slab where we store persistent Ops which has to be kept to completion
// if it is set, then all other bits are 0, that is whole user_data(u64) value is a key in slab

pub(crate) struct IOLoop {
    ring: IoUring,
    buf_ring: BufRing<MAX_EVENTS, RECVBUF_SIZE>,
    fixed_files: BitArr!(for NUM_FIXED_FILES),
    // ops which should persist to completion. slab key is used as a user_data in SQE/CQE
    ops: slab::Slab<Op>,

    // unsubmitted Ops
    pending_ops: VecDeque<Op>,

    // Stores timers user_data as requested by the app
    // Slab key is what goes into SQE/CQE user_data
    // Note: technically it can be just persistent Op in ops Slab, but we are going to have
    //       timer per connection and Op enum is quite larger than u64, it could be wasteful.
    timers: slab::Slab<u64>,
    stats: stats::Stats,
}

// Processes msghdr and extracts (gro_size, num_segments, SocketAddrV6)
// If there is no UDP_GRO control message, treat whole payload as single segment
fn io_msghdr_info(hdr: &RecvMsgOut) -> (u16, u16, Option<SocketAddrV6>) {
    let len = size_of::<libc::sockaddr_storage>();
    let addr = {
        let mut sockaddr_storage_buf = [0; size_of::<sockaddr_storage>()];
        sockaddr_storage_buf[..hdr.name_data().len()].copy_from_slice(hdr.name_data());
        unsafe {
            let storage = sockaddr_storage_buf
                .as_ptr()
                .cast::<libc::sockaddr_storage>()
                .read_unaligned();
            Some(socket2::SockAddr::new(storage, hdr.name_data().len() as _))
        }
        .and_then(|sockaddr| {
            if sockaddr.is_ipv6() {
                sockaddr.as_socket_ipv6()
            } else if let Some(sock4) = sockaddr.as_socket_ipv4() {
                Some(SocketAddrV6::new(
                    sock4.ip().to_ipv6_mapped(),
                    sock4.port(),
                    0,
                    0,
                ))
            } else {
                log::warn!("Unknown sockaddr: {sockaddr:?}");
                None
            }
        })
    };

    // Fake msghdr to iterate over control messages
    let mut mhdr = new_msghdr();
    mhdr.msg_controllen = hdr.control_data().len() as _;
    mhdr.msg_control = hdr.control_data().as_ptr() as _;

    let mut gro_size = hdr.payload_data().len() as u16;

    // SAFETY: msghdr.msg_controllen and msghdr.msg_control as valid
    unsafe {
        let mut cmsghdr = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(mhdr));

        while !cmsghdr.is_null() {
            let cmsg = &*cmsghdr;
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (libc::IPPROTO_UDP, libc::UDP_GRO) => {
                    gro_size = *(libc::CMSG_DATA(cmsg) as *const u16);
                    break;
                }
                _ => {
                    log::trace!(
                        "skipping unknown control message: level={} type={}",
                        cmsg.cmsg_level,
                        cmsg.cmsg_type
                    );
                }
            }
            cmsghdr = libc::CMSG_NXTHDR(&mhdr as *const _, cmsghdr);
        }
    }
    // Ceiling division. If there is division reminder, then produces +1
    let num_segments = (hdr.payload_data().len() as u16 + (gro_size - 1)) / gro_size;
    (gro_size, num_segments, addr)
}

pub(crate) struct IOProcessor<'a> {
    pending_ops: &'a mut VecDeque<Op>,
    buf_ring: &'a mut BufRing<MAX_EVENTS, RECVBUF_SIZE>,
    timers: &'a mut slab::Slab<TimerUserData>,
    stats: &'a mut Stats,
}

impl<'a> IOProcessor<'a> {
    fn process_cqe(
        &mut self,
        ops: &mut slab::Slab<Op>,
        cqe: &cqueue::Entry,
        handler: &mut impl IOEventHandler,
    ) {
        let key = cqe.user_data();
        if cqe.result() < 0 {
            log::warn!(
                "CQE error: {}",
                std::io::Error::from_raw_os_error((-cqe.result()).into())
            );
        }

        if let Some(op) = ops.get(key as _) {
            //FIXME: reaarm multishot
            let Op::RecvMsgMulti(op) = op else {
                unreachable!()
            };
            self.stats
                .record_cqe_opcode_count(opcode::RecvMsgMulti::CODE);
            self.process_recvmsg_multi(cqe.result(), cqe.flags(), &op, handler);
        } else {
            let opcode = (key >> MAX_EVENTS.ilog2()) as u8;
            if (opcode == 0xFF) {
                //timer
                // self.process_timer_cqe(cqe, key, handler);
            } else {
                // self.stats.record_cqe_opcode_count(opcode);
            }
        }
    }
    fn process_recvmsg_multi(
        &mut self,
        cqe_result: i32,
        cqe_flags: u32,
        op: &RecvMsgMultiOp,
        handler: &mut impl IOEventHandler,
    ) {
        if !cqueue::more(cqe_flags) {
            // multishot needs to be rearmed
            self.pending_ops
                .push_back(Op::RecvMsgMulti(RecvMsgMultiOp { ..*op }));
        }

        if cqe_result < 0 {
            log::error!(
                "recvmsg: {}",
                std::io::Error::from_raw_os_error(cqe_result.into())
            );
            return;
        }

        let Some((bid, buf)) = self.buf_ring.get(cqe_result as u32, cqe_flags) else {
            log::error!("No buffer for recvmsg");
            return;
        };
        let Ok(hdr) = RecvMsgOut::parse(buf, &op.msghdr) else {
            log::error!("RecvMsgOut::parse(buf)");
            self.buf_ring.return_buf(bid);
            return;
        };

        let (gro_size, num_segments, Some(sockaddr)) = io_msghdr_info(&hdr) else {
            return;
        };
        self.stats.record_recv_gso_count(num_segments as _);

        for pkt in hdr.payload_data().chunks(gro_size as _) {
            handler.handle_recvmsg(op.fixed, sockaddr, pkt)
        }
        self.buf_ring.return_buf(bid);
    }
}

impl<'a> crate::net::IO for IOProcessor<'a> {
    fn sendmsg(&mut self, from: Fixed, dest: SocketAddrV6, buf: bytes::Bytes) {
        self.pending_ops.push_back(Op::SendMsg(SendMsgOp {
            fixed: from,
            addr: dest.into(),
            buf,
            iov: MaybeUninit::uninit(),
            msghdr: MaybeUninit::uninit(),
        }));
    }
    fn timer_create(&mut self, duration: Duration, user_data: TimerUserData) -> Option<TimerKey> {
        if self.timers.len() >= u32::MAX as usize {
            return None;
        }
        // New timer setup
        let timer_key = TimerKey(self.timers.insert(user_data) as u32);
        self.pending_ops.push_back(Op::Timer(TimerOp {
            timer_key: TimerKey(timer_key.0),
            is_update: false,
            timespec: Some(duration.into()),
        }));
        Some(timer_key)
    }
    fn timer_update(
        &mut self,
        t: &TimerKey,
        duration: Duration,
        user_data: TimerUserData,
    ) -> std::io::Result<()> {
        match self.timers.get_mut(0) {
            Some(ud) => *ud = user_data,
            None => return Err(ErrorKind::NotFound.into()),
        }
        // Schedule timer update
        self.pending_ops.push_back(Op::Timer(TimerOp {
            timer_key: TimerKey(t.0 as _),
            is_update: true,
            timespec: Some(duration.into()),
        }));
        Ok(())
    }

    fn timer_delete(&mut self, key: TimerKey) -> std::io::Result<()> {
        // Schedule timer removal
        // Note: don't delete self.timers[key] yet, because might get reused by another call
        // to op_timer before we enter uring
        if !self.timers.contains(key.0 as _) {
            return Err(ErrorKind::NotFound.into());
        }
        self.pending_ops.push_back(Op::Timer(TimerOp {
            timer_key: TimerKey(key.0),
            is_update: false,
            timespec: None,
        }));
        Ok(())
    }
}

// Prepare SQEs and push them into Submission queue `sq`
fn io_push_pending(
    sq: &mut SubmissionQueue,
    ops: &mut slab::Slab<Op>,
    pending_ops: &mut VecDeque<Op>,
    stats: &mut stats::Stats,
) -> usize {
    let mut count = 0;
    for op in pending_ops.iter_mut() {
        if ops.len() >= MAX_EVENTS as _ {
            log::error!("Too many in-flight OPs, can't push more");
            break;
        }
        // This doesn't actually reserve space until we do entry.insert.
        let entry = ops.vacant_entry();
        let key = entry.key();

        stats.record_sqe_count(op);
        let sqe = {
            match op {
                Op::SendMsg(op) => {
                    let msghdr = op.msghdr.write(new_msghdr());

                    op.iov.write(libc::iovec {
                        iov_base: op.buf.as_ptr() as *mut _,
                        iov_len: op.buf.len() as _,
                    });

                    msghdr.msg_name = op.addr.as_ptr().addr() as *mut _;
                    msghdr.msg_namelen = op.addr.len() as _;
                    msghdr.msg_iov = op.iov.as_ptr() as *mut _;
                    msghdr.msg_iovlen = 1;

                    opcode::SendMsg::new(op.fixed, msghdr as *const _)
                        .build()
                        .flags(Flags::SKIP_SUCCESS)
                        // store opcode as userdata for stats, but we can't use bits which
                        // otherwise used for MAX_EVENTS
                        .user_data((opcode::SendMsg::CODE as u64) << MAX_EVENTS.ilog2())
                }
                Op::RecvMsgMulti(op) => {
                    let Op::RecvMsgMulti(op) =
                        entry.insert(Op::RecvMsgMulti(RecvMsgMultiOp { ..*op }))
                    else {
                        unreachable!()
                    };

                    op.build().user_data(key as _)
                }
                Op::Timer(op) => {
                    let timer_user_data: u64 =
                        (op.timer_key.0 as u64) << 32 | (op.opcode() as u64) << MAX_EVENTS.ilog2();
                    if let Some(timespec) = op.timespec.as_ref() {
                        if op.is_update {
                            // Update timer to new timespec
                            opcode::TimeoutUpdate::new(timer_user_data, timespec as *const _)
                                .build()
                        } else {
                            opcode::Timeout::new(timespec as *const _).build()
                        }
                    } else {
                        // Remove timer
                        opcode::TimeoutRemove::new(timer_user_data).build()
                    }
                }
            }
        };
        log::trace!("sqe: {:?}", sqe);
        // SAFETY: op where all pointers are pointing to remains valid until we submit
        let res = unsafe { sq.push(&sqe) };
        if let Err(_) = res {
            log::error!("sq.push() failed");
            break;
        }

        count += 1
    }
    sq.sync();
    count
}

impl IOLoop {
    pub fn new() -> IOLoop {
        log::debug!("Creating BufRing");
        let mut buf_ring: BufRing<MAX_EVENTS, RECVBUF_SIZE> = BufRing::new(0);
        log::debug!("Creating IOLoop");

        IOLoop {
            ring: Self::init_ring(&mut buf_ring),
            buf_ring,
            fixed_files: BitArray::ZERO,
            ops: slab::Slab::with_capacity(MAX_EVENTS as usize),
            pending_ops: VecDeque::new(),
            timers: slab::Slab::new(),
            stats: stats::Stats::default(),
        }
    }

    fn init_ring(buf_ring: &mut BufRing<MAX_EVENTS, RECVBUF_SIZE>) -> IoUring {
        let ring = IoUring::builder()
            .setup_defer_taskrun()
            .setup_coop_taskrun()
            .setup_single_issuer()
            .setup_submit_all()
            .dontfork()
            .setup_cqsize(MAX_EVENTS as u32)
            .build(MAX_EVENTS as u32)
            .unwrap();

        // SAFETY: ring_addr is valid for the lifetime of the ring
        //         because they are kept together in the struct
        unsafe {
            ring.submitter()
                .register_buf_ring(
                    buf_ring.ring_addr().addr().try_into().unwrap(),
                    buf_ring.ring_count(),
                    buf_ring.bgid(),
                )
                .expect("Failed to register buffer ring");
        }
        ring.submitter()
            .register_files_sparse(NUM_FIXED_FILES as u32)
            .expect("Failed to register sparse files table");
        ring
    }

    // Register OS file descriptor with io_uring. Makes it more efficient to work with
    // when in subsequent ops it is referenced by the returned Fixed.
    pub fn register_fd(&mut self, fd: std::os::fd::RawFd) -> std::io::Result<Fixed> {
        let fixed_fd = self
            .fixed_files
            .first_zero()
            .ok_or(std::io::ErrorKind::QuotaExceeded)?;
        self.fixed_files.set(fixed_fd, true);
        self.ring
            .submitter()
            .register_files_update(fixed_fd as u32, &[fd])?;
        Ok(Fixed(fixed_fd as _))
    }

    pub fn unregister_fd(&mut self, fixed: Fixed) -> std::io::Result<()> {
        let bit: bool = self.fixed_files[fixed.0 as usize];
        if !bit {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        self.ring
            .submitter()
            .register_files_update(fixed.0 as u32, &[-1])?;
        self.fixed_files.set(fixed.0 as _, false);
        Ok(())
    }

    pub fn op_recv_multishot(&mut self, fixed: Fixed) {
        self.pending_ops.push_back(Op::RecvMsgMulti(RecvMsgMultiOp {
            fixed,
            bgid: self.buf_ring.bgid(),
            msghdr: new_msghdr(),
        }));
    }

    pub fn run_loop(&mut self, handler: &mut impl IOEventHandler) {
        let (submitter, mut sq, mut cq) = self.ring.split();
        loop {
            let count_pushed = io_push_pending(
                &mut sq,
                &mut self.ops,
                &mut self.pending_ops,
                &mut self.stats,
            );
            let res = submitter
                .submit_and_wait(1)
                .or_else(|err| {
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        Ok(0)
                    } else {
                        Err(err)
                    }
                })
                .unwrap();
            if res != count_pushed {
                log::warn!("Not all ops where successfull, expect failing CQEs");
            }
            self.pending_ops.drain(..count_pushed);

            // Workaround borrow checker because we borrowed &self.ring above
            let mut processor = IOProcessor {
                pending_ops: &mut self.pending_ops,
                buf_ring: &mut self.buf_ring,
                timers: &mut self.timers,
                stats: &mut self.stats,
            };
            log::info!("cqe count: {}", cq.len());

            for cqe in &mut cq {
                log::trace!("cqe: {:?}", cqe);
                processor.process_cqe(&mut self.ops, &cqe, handler);
            }
            self.buf_ring.sync();
            cq.sync();
        }
    }
}

impl<'a> From<&'a mut IOLoop> for IOProcessor<'a> {
    fn from(value: &'a mut IOLoop) -> Self {
        Self {
            pending_ops: &mut value.pending_ops,
            buf_ring: &mut value.buf_ring,
            timers: &mut value.timers,
            stats: &mut value.stats,
        }
    }
}
