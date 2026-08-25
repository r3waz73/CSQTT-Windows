// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Result, bail};
use std::fs::File;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
pub async fn receive_fd(name: String, cancel: CancellationToken) -> Result<File> {
    tokio::task::spawn_blocking(move || receive_fd_blocking(&name, &cancel)).await?
}

#[cfg(unix)]
fn receive_fd_blocking(name: &str, cancel: &CancellationToken) -> Result<File> {
    use nix::{
        cmsg_space,
        errno::Errno,
        sys::socket::{
            AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
            accept, bind, listen, recvmsg, socket,
        },
    };
    use std::{
        io::IoSliceMut,
        os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        thread,
        time::Duration,
    };

    fn configure_nonblocking(descriptor: RawFd) -> Result<()> {
        let status = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if status == -1
            || unsafe { libc::fcntl(descriptor, libc::F_SETFL, status | libc::O_NONBLOCK) } == -1
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    let listener = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    bind(
        listener.as_raw_fd(),
        &UnixAddr::new_abstract(name.as_bytes())?,
    )?;
    listen(&listener, Backlog::new(1)?)?;
    let connection = loop {
        if cancel.is_cancelled() {
            bail!("TUN FD wait cancelled");
        }
        match accept(listener.as_raw_fd()) {
            Ok(descriptor) => {
                let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                configure_nonblocking(descriptor.as_raw_fd())?;
                break descriptor;
            }
            Err(Errno::EAGAIN) => thread::sleep(Duration::from_millis(25)),
            Err(error) => return Err(error.into()),
        }
    };
    let mut data = [0u8; 1];
    loop {
        if cancel.is_cancelled() {
            bail!("TUN FD receive cancelled");
        }
        let mut slices = [IoSliceMut::new(&mut data)];
        let mut ancillary = cmsg_space!([std::os::fd::RawFd; 1]);
        match recvmsg::<UnixAddr>(
            connection.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary),
            MsgFlags::empty(),
        ) {
            Ok(message) => {
                if message.bytes == 0 {
                    bail!("TUN FD connection closed");
                }
                for control in message.cmsgs()? {
                    if let ControlMessageOwned::ScmRights(descriptors) = control
                        && let Some(descriptor) = descriptors.into_iter().next()
                    {
                        let file = unsafe { File::from_raw_fd(descriptor) };
                        configure_nonblocking(file.as_raw_fd())?;
                        return Ok(file);
                    }
                }
                bail!("no fd received");
            }
            Err(Errno::EAGAIN) => thread::sleep(Duration::from_millis(25)),
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(not(unix))]
pub async fn receive_fd(_name: String, _cancel: CancellationToken) -> Result<File> {
    bail!("TUN FD transport is available only on Android and Unix")
}
