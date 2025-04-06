mod transport;

use std::net::SocketAddrV6;

type ConnId = usize;
type StreamId = usize;

// What happens as a result of feeding packet/timer data
enum Event {
    Connected(ConnId, Endpoints),
    Accepted(ConnId, Endpoints),
    StreamOpened(ConnId, StreamId),
    StreamClosed(ConnId, StreamId),
    StreamRecv(ConnId, StreamId, bytes::Bytes), // bytes received
    StreamSent(ConnId, StreamId, usize),        //sent bytes offset acked
    DatagramReceived(ConnId, bytes::Bytes),
}

type Endpoints = (SocketAddrV6, SocketAddrV6); //local,remote

// High level interface aggregating across all connections
trait QUIC {
    fn connect(&mut self, endpoints: &Endpoints) -> ConnId;
    fn disconnect(&mut self, conn_id: ConnId);
    fn send_stream(
        &mut self,
        conn_id: ConnId,
        stream_id: StreamId,
        buf: &[u8],
    ) -> std::io::Result<usize>;
    fn send_datagram(&mut self, conn_id: ConnId, buf: &[u8]) -> std::io::Result<usize>;

    fn poll(&mut self) -> impl Iterator<Item = Event>;

    // fn feed_packet(
    //     &mut self,
    //     now: Instant,
    //     ep: &Endpoints,
    //     buf: &mut [u8],
    // ) -> impl Iterator<Item = Event>;
    //
    // fn feed_expiry_timer(&mut self, conn_id: ConnId) -> impl Iterator<Item = Event>;
}
