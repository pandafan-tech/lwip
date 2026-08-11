#![doc = include_str!("../README.md")]

mod lwip;
mod mutex;
mod output;
mod packet;
mod pbuf_pool;
mod stack;
mod stack_impl;
mod tcp_listener;
mod tcp_listener_impl;
mod tcp_stream;
mod tcp_stream_context;
mod tcp_stream_impl;
mod udp;
mod util;

pub(crate) static LWIP_MUTEX: mutex::AtomicMutex = mutex::AtomicMutex::new();
pub(crate) use mutex::AtomicMutexGuard as LWIPMutexGuard;

pub use packet::{
    packet_pool_runtime_stats, trim_packet_pools, IpPacket, PacketPool, PacketPoolsRuntimeStats,
};
pub use pbuf_pool::{configure_pbuf_pool_capacity, pbuf_pool_runtime_stats, PbufPoolRuntimeStats};
pub use stack::{NetStack, StackEgress, StackIngress};
pub use stack_impl::{initialize_windows_runtime_config, set_tcp_tx_partial_checksum};
pub use tcp_listener::TcpListener;
pub use tcp_stream::TcpStream;
pub use tcp_stream_context::{tcp_runtime_stats, TcpRuntimeStats};
pub use {
    udp::udp_runtime_stats, udp::RecvHalf as UdpRecvHalf, udp::SendHalf as UdpSendHalf,
    udp::UdpPkt, udp::UdpRuntimeStats, udp::UdpSocket,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("LwIP error ({0})")]
    LwIP(i8),

    #[error("AtomicMutexErr {0:?}")]
    AtomicMutexErr(#[from] mutex::AtomicMutexErr),

    #[error("runtime configuration error: {0}")]
    RuntimeConfig(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
