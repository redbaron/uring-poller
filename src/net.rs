pub use ::io_uring::types::Fixed;

mod buf_ring;
mod io_uring;
mod stats;

pub(crate) use io_uring::{IOLoop, IOProcessor};
pub struct TimerKey(u32);
type TimerUserData = u64;

pub(crate) trait IO {
    fn sendmsg(&mut self, from: Fixed, dest: std::net::SocketAddrV6, buf: bytes::Bytes);
    // Schedule a timer to fire after duration returning TimerKey, which can be
    // used to cancel or update the timer.
    fn timer_create(
        &mut self,
        duration: std::time::Duration,
        user_data: TimerUserData,
    ) -> Option<TimerKey>;

    fn timer_update(
        &mut self,
        t: &TimerKey,
        duration: std::time::Duration,
        user_data: TimerUserData,
    ) -> std::io::Result<()>;
    fn timer_delete(&mut self, t: TimerKey) -> std::io::Result<()>;
}

pub(crate) trait IOEventHandler {
    fn handle_recvmsg(&self, to: Fixed, from: std::net::SocketAddrV6, buf: &[u8]);
    // fn handle_timer(&self, timer_key: TimerKey);
}
