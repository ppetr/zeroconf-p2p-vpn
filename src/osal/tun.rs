use anyhow::Error;
use futures_util::stream::TryStreamExt;
use nix::libc;
use rtnetlink::Handle;
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use tokio_uring::fs::File;

use crate::osal::Globals;

// 1. Fixed: Use ioctl_write_ptr_bad! for commands passing a struct pointer.
// This generates a type-safe function signature that accepts an *const libc::ifreq parameter.
nix::ioctl_write_ptr_bad!(tunsetiff, libc::TUNSETIFF, libc::ifreq);

pub struct Tun<'g> {
    globals: &'g Globals,
    pub file: File,
    pub if_name: String,
    if_index: u32,
}

impl<'g> Tun<'g> {
    pub async fn new(globals: &'g Globals, if_name: Option<&str>) -> Result<Tun<'g>, Error> {
        let (file, if_name) = open_tun_uring(if_name)?;
        let if_index = get_if_index(&globals.rtnetlink, if_name.clone()).await?;
        Ok(Tun {
            globals,
            file,
            if_name,
            if_index: if_index.expect("Missing interface index"),
        })
    }
}

async fn get_if_index(handle: &Handle, if_name: String) -> Result<Option<u32>, rtnetlink::Error> {
    let mut links = handle.link().get().match_name(if_name.clone()).execute();
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
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE) as i16;

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
