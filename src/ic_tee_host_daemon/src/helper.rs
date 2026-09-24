use std::time::Duration;
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
