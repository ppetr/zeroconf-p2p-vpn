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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn transient_errnos_are_retryable() {
        for errno in [
            libc::EAGAIN,
            libc::EINTR,
            libc::EINVAL,
            libc::EMSGSIZE,
            libc::ENOBUFS,
        ] {
            assert!(
                is_tun_transient(&Error::from_raw_os_error(errno)),
                "errno {errno} should be treated as transient"
            );
        }
    }

    #[test]
    fn unlisted_errnos_are_not_retryable() {
        for errno in [libc::EPERM, libc::EACCES, libc::EPIPE, libc::ENOENT] {
            assert!(
                !is_tun_transient(&Error::from_raw_os_error(errno)),
                "errno {errno} should not be treated as transient"
            );
        }
    }

    #[test]
    fn errors_without_an_os_code_are_not_retryable() {
        assert!(!is_tun_transient(&Error::new(
            ErrorKind::Other,
            "not an OS error"
        )));
    }
}
