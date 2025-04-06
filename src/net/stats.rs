use crate::net::io_uring::Op;

#[derive(Default)]
struct OpsCount {
    recvmsg_multi: u32,
    sendmsg: u32,
    timeout_new: u32,
    timeout_remove: u32,
    timeout_update: u32,
}

#[derive(Default)]
pub(crate) struct Stats {
    sqe_count: OpsCount,

    // CQE don't have opcodes, count them by SQE opcode they were produced by.
    // CQE counts might not be equal to SQE counts, because:
    // - multishot SQEs produce multiple CQEs
    // - SQE with SKIP_SUCCESS don't produce any CQE
    cqe_count: OpsCount,

    // poor man's histogram: index is number of gso segments we received
    // index 0 is count for >=16 segments
    recv_gso_count: [u32; 16],
}

impl Stats {
    pub fn record_sqe_count(&mut self, op: &Op) {
        match op {
            Op::SendMsg(_) => self.sqe_count.sendmsg += 1,
            Op::RecvMsgMulti(_) => self.sqe_count.recvmsg_multi += 1,
            Op::Timer(op) => {
                if op.is_update {
                    self.sqe_count.timeout_update += 1;
                } else if op.timespec.is_some() {
                    self.sqe_count.timeout_new += 1;
                } else {
                    self.sqe_count.timeout_new += 1;
                }
            }
        }
    }

    pub fn record_recv_gso_count(&mut self, segments: u16) {
        let idx = if segments >= 16 { 0 } else { segments };
        self.recv_gso_count[idx as usize] += 1;
    }

    pub fn record_cqe_opcode_count(&mut self, opcode: u8) {
        match opcode {
            io_uring::opcode::SendMsg::CODE => self.cqe_count.sendmsg += 1,
            io_uring::opcode::RecvMsgMulti::CODE => self.cqe_count.recvmsg_multi += 1,
            io_uring::opcode::Timeout::CODE => self.cqe_count.timeout_new += 1,
            io_uring::opcode::TimeoutUpdate::CODE => self.cqe_count.timeout_update += 1,
            io_uring::opcode::TimeoutRemove::CODE => self.cqe_count.timeout_remove += 1,
            _ => {
                log::error!("Unknown opcode in CQE: {}", opcode);
            }
        }
    }
}
