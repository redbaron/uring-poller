use std::marker::PhantomPinned;
use std::sync::atomic;

//struct io_uring_buf in liburing
#[repr(C)]
struct BufRingEntry {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
}

// Box::new() constructs argument on the stack and then copies to heap.
// For large buffers we need to construct it inplace on the heap withtout blowing up stack.
fn box_new_zeroed<T>() -> Box<T> {
    unsafe {
        let mut uninit = Box::<T>::new_uninit();
        let ptr = uninit.as_mut_ptr();
        // SAFETY: we take this pointer from Box, so it is both valid and properly aligned
        ptr.write_bytes(0u8, 1);
        // SAFETY: all zeroes is a valid initialized state
        uninit.assume_init()
    }
}

// Memory allocated for the buffer ring must be page aligned
#[repr(C, align(4096))]
pub(super) struct BufRingMem<const COUNT: usize>([BufRingEntry; COUNT], PhantomPinned);

pub(super) struct BufId(u16);

// BufRing is a structure to support io-uring provided buffers
// as described in https://man.archlinux.org/man/extra/liburing/io_uring_register_buf_ring.3.en
// Params:
//   - COUNT: number of buffers in the ring. MUST be a power of 2
//   - LEN: size of each buffer
pub(super) struct BufRing<const COUNT: usize, const LEN: usize> {
    //bgid is the buffer group ID associated with this ring.
    bgid: u16,

    // Offset in bring where the next buffer will be returned
    tail: u16,

    // this just stores table of descriptors, actual buffers are in bufs
    // we Pin because this pointer is passed to the kernel and must not move
    bring: std::pin::Pin<Box<BufRingMem<COUNT>>>,

    // we Pin because buf ring we passed to kernel points to these buffers and therefore they must not move
    bufs: std::pin::Pin<Box<([[u8; LEN]; COUNT], PhantomPinned)>>,
}

impl<const COUNT: usize, const LEN: usize> BufRing<COUNT, LEN> {
    // const_assert!(COUNT.is_power_of_two() && COUNT > 0 && COUNT < 32768);

    const MASK: u16 = COUNT as u16 - 1;
    pub fn new(bgid: u16) -> Self {
        let mut v = Self {
            bgid,
            tail: 0,
            bring: Box::into_pin(box_new_zeroed()),
            bufs: Box::into_pin(box_new_zeroed()),
        };

        for i in 0..v.bufs.0.len() {
            v.return_buf(BufId(i as _));
        }
        v.sync();
        v
    }

    pub fn ring_addr(&self) -> *const BufRingMem<COUNT> {
        self.bring.as_ref().get_ref()
    }

    pub const fn ring_count(&self) -> u16 {
        COUNT as u16
    }

    pub fn bgid(&self) -> u16 {
        self.bgid
    }

    // Access buf selected by io-uring. |res| and |flags| are from CQE directly
    pub fn get(&self, res: u32, flags: u32) -> Option<(BufId, &[u8])> {
        let bid = io_uring::cqueue::buffer_select(flags)?;
        let len = res as usize;
        Some((BufId(bid), &self.bufs.0[bid as usize][..len]))
    }

    // Returns buffer to the ring. It updates values locally, but requires
    // committing the changes to the kernel with method:`sync`
    // Ref: io_uring_buf_ring_add
    pub fn return_buf(&mut self, bid: BufId) {
        // SAFETY: BufId are handed to the app when buffer is released by kernel,
        //         so the BufRingEntry we about to update is guaranteed to be not in use.
        //         Here we consume BufId, so caller can't call it again without obtaining buffer legitimately.
        let bufring = unsafe { &mut self.bring.as_mut().get_unchecked_mut().0 };
        let entry = &mut bufring[(self.tail & Self::MASK) as usize];
        entry.addr = self.bufs.0[bid.0 as usize].as_ptr() as _;
        entry.len = LEN as _;
        entry.bid = bid.0;
        entry.resv = 0;
        // Interesting that tail is allowed to grow beyond COUNT. It is fine, because
        // it is always used with `& MASK` to get the actual index.
        self.tail = self.tail.wrapping_add(1);
    }

    // Commit added buffers to the kernel.
    // Ref: io_uring_buf_ring_advance
    pub fn sync(&mut self) {
        // io_uring_buf_ring
        // SAFETY:
        // - ptr is aligned because it points to an u16 field in repr(C) struct
        // - ptr is valid
        // - we are not accessing this u16 value from anywhere else in this program
        let tail = unsafe {
            let bufring = &mut self.bring.as_mut().get_unchecked_mut().0;
            atomic::AtomicU16::from_ptr(&raw mut bufring[0].resv)
        };
        tail.store(self.tail, atomic::Ordering::Release);
    }
}
