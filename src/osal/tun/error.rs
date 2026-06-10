use libc;

macro_rules! match_libc_errors {
    ($os_err:expr, $($error:ident),* $(,)?) => {
        match $os_err {
            $(libc::$error => Some(stringify!($error)),)*
            _ => None,
        }
    };
}

/// If `err` can be considered retryiable for a TUN device, returns `()`. Otherwise
pub fn is_tun_transient(err: &std::io::Error) -> bool {
    if let Some(os_err) = err.raw_os_error() {
        if let Some(err_label) =
            match_libc_errors!(os_err, EAGAIN, EINTR, EINVAL, EMSGSIZE, ENOBUFS)
        {
            tracing::debug!(
                target: "tun_io",
                error = %err_label,
                "Transient TUN error"
            );
            metrics::counter!("tun_temporary_errors_total", "error" => err_label).increment(1);
            return true;
        }
    }
    false
}
