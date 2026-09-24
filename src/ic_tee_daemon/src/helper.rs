// Borrowed with love from oyster-tcp-proxy
// https://github.com/marlinprotocol/oyster-tcp-proxy

use std::{io, net::SocketAddrV4, time::Duration};
use tokio::net::TcpStream;
use tokio_vsock::VsockAddr;

/// Buffer size of each direction when proxying a connection.
pub const COPY_BUF_SIZE: usize = 64 * 1024;
/// Delay before accepting again after an accept error (e.g. too many open files).
pub const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

pub fn split_vsock(addr: &str) -> Result<VsockAddr, String> {
    let (cid, port) = addr
        .split_once(':')
        .ok_or("invalid vsock address, should contain one : (colon)".to_string())?;
    let cid: u32 = cid
        .parse()
        .map_err(|_| format!("failed to parse cid {} as a u32", cid))?;
    let port: u32 = port
        .parse()
        .map_err(|_| format!("failed to parse port {} as a u32", port))?;

    Ok(VsockAddr::new(cid, port))
}

/// Returns the original IPv4 destination of a connection redirected by iptables.
#[cfg(target_os = "linux")]
pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddrV4> {
    use std::{mem, net::Ipv4Addr, os::unix::io::AsRawFd};

    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn original_dst(_stream: &TcpStream) -> io::Result<SocketAddrV4> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST is only supported on Linux",
    ))
}
