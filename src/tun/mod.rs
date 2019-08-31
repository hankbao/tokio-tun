use std::fmt;
use std::io::{self, Read, Write};

use bytes::{Buf, BufMut, Bytes};
use futures::{Async, AsyncSink, Poll, Sink, StartSend, Stream};
use mio::Ready;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::reactor::PollEvented2;

#[cfg(not(windows))]
use nix::libc::{c_char, c_short, sockaddr};
#[cfg(not(windows))]
use std::net::Ipv4Addr;
#[cfg(not(windows))]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use ipnetwork::{IpNetwork, Ipv4Network};
#[cfg(windows)]
use winapi::shared::guiddef::GUID;

use crate::try_nb;

#[cfg(not(windows))]
fn from_nix_error(err: ::nix::Error) -> io::Error {
    match err {
        ::nix::Error::Sys(e) => e.into(),
        _ => unreachable!(),
    }
}

#[cfg(not(windows))]
#[macro_export]
macro_rules! try_nix {
    ($expr:expr) => {
        match $expr {
            ::std::result::Result::Ok(val) => val,
            ::std::result::Result::Err(err) => match err {
                ::nix::Error::Sys(e) => {
                    return ::std::result::Result::Err(::std::convert::From::from(e))
                }
                _ => unreachable!(),
            },
        }
    };
}

#[cfg(not(windows))]
const IFNAMSIZ: usize = 16;

#[cfg(not(windows))]
#[repr(C)]
pub struct ifreq_addr {
    pub ifra_name: [c_char; IFNAMSIZ],
    pub ifra_addr: sockaddr,
}

#[cfg(not(windows))]
#[repr(C)]
pub struct ifreq_flags {
    pub ifra_name: [c_char; IFNAMSIZ],
    pub ifra_flags: c_short,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "macos.rs"]
pub mod platform;

#[cfg(any(target_os = "linux"))]
#[path = "linux.rs"]
pub mod platform;

#[cfg(windows)]
#[path = "windows.rs"]
pub mod platform;

pub struct Tun {
    io: PollEvented2<platform::Tun>,
}

impl Tun {
    /// New Tun to the existing event pool.
    #[cfg(not(windows))]
    pub fn new() -> io::Result<Tun> {
        Tun::from_tun(platform::Tun::new()?)
    }

    /// New Tun to the existing event pool.
    #[cfg(windows)]
    pub fn new(ifname: String, description: String, requested_guid: &GUID) -> io::Result<Tun> {
        Tun::from_tun(platform::Tun::new(ifname, description, requested_guid)?)
    }

    /// New Tun to the existing event pool from the existig underlying Tun implementation.
    pub fn from_tun(tun: platform::Tun) -> io::Result<Tun> {
        Ok(Tun {
            io: PollEvented2::new(tun),
        })
    }

    /// Get interface name from the underlying Tun.
    pub fn ifname(&self) -> io::Result<String> {
        self.io.get_ref().ifname()
    }

    /// Set address of the Tun interface
    #[cfg(windows)]
    pub fn set_addr(&mut self, addr: Ipv4Network) -> io::Result<()> {
        self.io.get_mut().set_addr(addr)
    }

    /// Get address of the Tun interface
    #[cfg(windows)]
    pub fn addr(&self) -> io::Result<IpNetwork> {
        self.io.get_ref().addr()
    }

    /// Set address of the Tun interface
    #[cfg(not(windows))]
    pub fn set_addr(&self, addr: Ipv4Addr) -> io::Result<()> {
        self.io.get_ref().set_addr(addr)
    }

    /// Set netmask of the Tun interface
    #[cfg(not(windows))]
    pub fn set_netmask(&self, netmask: Ipv4Addr) -> io::Result<()> {
        self.io.get_ref().set_netmask(netmask)
    }

    /// Get address of the Tun interface
    #[cfg(not(windows))]
    pub fn addr(&self) -> io::Result<Ipv4Addr> {
        self.io.get_ref().addr()
    }

    /// Get netmask of the Tun interface
    #[cfg(not(windows))]
    pub fn netmask(&self) -> io::Result<Ipv4Addr> {
        self.io.get_ref().netmask()
    }

    /// Poll Tun for read
    pub fn poll_read_ready_readable(&self) -> io::Result<Async<Ready>> {
        self.io.poll_read_ready(Ready::readable())
    }

    /// Poll Tun for write
    pub fn poll_write_ready(&self) -> io::Result<Async<Ready>> {
        self.io.poll_write_ready()
    }
}

#[cfg(not(windows))]
impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.read(buf)
    }
}

impl<'a> Read for &'a Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.io).read(buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<'a> Write for &'a Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.io).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.io).flush()
    }
}

impl AsyncRead for Tun {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }

    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        if let Async::NotReady = self.io.poll_read_ready(Ready::readable())? {
            return Ok(Async::NotReady);
        }

        let mut stack_buf = [0u8; 1600]; // TODO: Use MTU
        let read_result = self.io.read(&mut stack_buf);
        match read_result {
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.clear_read_ready(Ready::readable())?;
                    Ok(Async::NotReady)
                } else {
                    Err(e)
                }
            }
            Ok(bytes_read) => {
                buf.put_slice(&stack_buf[0..bytes_read]);
                Ok(Async::Ready(bytes_read))
            }
        }
    }
}

impl AsyncWrite for Tun {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(().into())
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        if let Async::NotReady = self.io.poll_write_ready()? {
            return Ok(Async::NotReady);
        }

        let bytes: Bytes = buf.collect();
        let write_result = self.io.write(&bytes[..]);
        match write_result {
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.clear_write_ready()?;
                    Ok(Async::NotReady)
                } else {
                    Err(e)
                }
            }
            Ok(bytes_written) => {
                buf.advance(bytes_written);

                if bytes_written < bytes.len() {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write packet to tun",
                    ))
                } else {
                    Ok(Async::Ready(bytes_written))
                }
            }
        }
    }
}

impl Stream for Tun {
    type Item = Box<[u8]>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Async::NotReady = self.io.poll_read_ready(Ready::readable())? {
            return Ok(Async::NotReady);
        }

        let mut buf = vec![0u8; 1600]; // TODO: Use MTU
        let read_result = self.io.read(&mut buf);
        match read_result {
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.clear_read_ready(Ready::readable())?;
                    Ok(Async::NotReady)
                } else {
                    Err(e)
                }
            }
            Ok(bytes_read) => {
                buf.truncate(bytes_read);
                Ok(Async::Ready(Some(buf.into_boxed_slice())))
            }
        }
    }
}

impl Sink for Tun {
    type SinkItem = Box<[u8]>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        if let Async::NotReady = self.io.poll_write_ready()? {
            return Ok(AsyncSink::NotReady(item));
        }

        let write_result = self.io.write(&item[..]);
        match write_result {
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.clear_write_ready()?;
                    Ok(AsyncSink::NotReady(item))
                } else {
                    Err(e)
                }
            }
            Ok(bytes_written) => {
                if bytes_written < item.len() {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write packet to tun",
                    ))
                } else {
                    Ok(AsyncSink::Ready)
                }
            }
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        try_nb!(self.io.flush());
        Ok(Async::Ready(()))
    }
}

impl fmt::Debug for Tun {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.io.get_ref().fmt(f)
    }
}
