pub mod error;

use anyhow::{Context, Result};
use futures_util::stream::TryStreamExt;
use nix::libc;
use rtnetlink::Handle;
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use tokio::sync::mpsc;
use tokio_uring::fs::File;

use crate::osal::BufferPool;
use crate::osal::Globals;
use crate::osal::PooledSlice;
use crate::osal::ScopedIfAddr;
use crate::osal::ScopedRoute;

// 1. Fixed: Use ioctl_write_ptr_bad! for commands passing a struct pointer.
// This generates a type-safe function signature that accepts an *const libc::ifreq parameter.
nix::ioctl_write_ptr_bad!(tunsetiff, libc::TUNSETIFF, libc::ifreq);

pub struct TunControlOpts {
    pub buffer_pool: usize,
    pub tx_packet: mpsc::Receiver<PooledSlice>,
    pub rx_packet: mpsc::Sender<PooledSlice>,
}

pub struct Tun<'g> {
    globals: &'g Globals,
    pub file: File,
    pub if_name: String,
    if_index: u32,
}

impl<'g> Tun<'g> {
    pub async fn new(globals: &'g Globals, if_name: Option<&str>) -> Result<Tun<'g>> {
        let (file, if_name) = open_tun_uring(if_name)?;
        let if_index: u32 = get_if_index(&globals.rtnetlink, if_name.clone())
            .await?
            .context("unable to determine the interface index")?;
        let this = Tun {
            globals,
            file,
            if_name,
            if_index: if_index,
        };
        this.link_up().await?;
        Ok(this)
    }

    async fn link_up(&self) -> Result<()> {
        self.globals
            .rtnetlink
            .link()
            .set(
                rtnetlink::LinkUnspec::new_with_index(self.if_index)
                    .up()
                    .build(),
            )
            .execute()
            .await?;
        Ok(())
    }

    pub async fn add_if_addr(self: &Self, ip: IpAddr) -> Result<ScopedIfAddr> {
        ScopedIfAddr::new(self.globals, self.if_index, ip)
            .await
            .context("when registering interface address")
    }

    pub async fn add_route(self: &Self, ip: IpAddr) -> Result<ScopedRoute> {
        ScopedRoute::new(self.globals, self.if_index, ip)
            .await
            .context("when registering route")
    }

    pub async fn control(&self, opts: TunControlOpts) -> Result<()> {
        let mut buffer_pool = BufferPool::new(opts.buffer_pool, 2048)?;

        let file_ref = &self.file;
        let rx_packet = opts.rx_packet;
        let rx_task = async move {
            Ok::<(), anyhow::Error>(loop {
                let buf = match buffer_pool.pop().await.read_frame(&file_ref).await {
                    Err(err) if error::is_tun_transient(&err) => continue,
                    r => r?,
                };
                if !buf.is_empty() {
                    rx_packet.send(buf).await?;
                }
            })
        };
        let mut tx_packet = opts.tx_packet;
        let tx_task = async move {
            Ok::<(), anyhow::Error>(loop {
                let buf = tx_packet.recv().await.context("Channel dropped")?;
                match buf.write_frame(&file_ref).await {
                    Err(err) if error::is_tun_transient(&err) => continue,
                    r => r?,
                };
            })
        };
        tokio::select! {
            err = rx_task => {
                err.context("rx task")
            }
            err = tx_task => {
                err.context("tx task")
            }
        }
    }
}

async fn get_if_index(handle: &Handle, if_name: String) -> Result<Option<u32>, rtnetlink::Error> {
    let mut links = handle.link().get().match_name(if_name).execute();
    Ok(links.try_next().await?.map(|l| l.header.index))
}

/// Opens a TUN device, configures a Multi-Queue interface using standard system definitions,
/// and builds a tokio-uring driver file instance directly.
///
/// - `if_name`: `Some("tun0")` to hook into a specific layout, or `None` to auto-allocate.
/// - Returns: A tuple containing the `tokio_uring::fs::File` and the validated interface `String`.
fn open_tun_uring(if_name: Option<&str>) -> std::io::Result<(File, String)> {
    // Open the control interface device
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/net/tun")?;

    // Zero-initialize the standard libc configuration frame safely
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Assign multi-queue flag layouts
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;

    // Apply the name filter if a query pattern template is provided
    if let Some(name) = if_name {
        let bytes = name.as_bytes();
        if bytes.len() >= ifr.ifr_name.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Name too long",
            ));
        }
        let name_buffer = unsafe { &mut *(&mut ifr.ifr_name as *mut [libc::c_char] as *mut [u8]) };
        name_buffer[..bytes.len()].copy_from_slice(bytes);
    }

    // 2. Fixed: Call the ptr-based wrapper directly without unsafe pointer-to-usize conversions.
    // Nix handles OS return value tracking internally.
    unsafe { tunsetiff(file.as_raw_fd(), &ifr) }
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    // 3. Fixed: Decouple CStr extraction and UTF-8 string casting
    // This avoids incompatible Error types inside 'and_then' blocks.
    let name_buffer = unsafe { &*(&ifr.ifr_name as *const [libc::c_char] as *const [u8]) };

    let c_str = CStr::from_bytes_until_nul(name_buffer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let final_name = c_str
        .to_str()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .to_string();

    // Pass everything directly up into the tokio-uring driver architecture
    let owned_fd = OwnedFd::from(file);
    let tokio_uring_file = File::from_std(std::fs::File::from(owned_fd));

    Ok((tokio_uring_file, final_name))
}
