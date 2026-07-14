use anyhow;
use metrics;
use std::io::ErrorKind;
use thin_status::*;

/// Holds an `ErrorCode` and an `ErrorKind` for conversion into `Vec<metrics::Label>`.
pub struct ExtractedErrorCode {
    pub code: ErrorCode,
    pub kind: std::io::ErrorKind,
}

impl ExtractedErrorCode {
    /// Extracts `ErrorKind` from `error` and also converts it into `ErrorCode`.
    pub fn from_io(error: &std::io::Error) -> Self {
        let kind = error.kind();
        Self {
            code: ErrorCode::from_error_kind(kind),
            kind,
        }
    }

    /// Extracts `std::io::Error` and `ThinStatus` from `error`. If there is no `ThinStatus` in
    /// `error` then it converts the `ErrorKind` into `ErrorCode` as well. If there is no available
    /// information, returns `ErrorCode::Unknown` and/or `ErrorKind::Other`.
    pub fn from_anyhow(error: &anyhow::Error) -> Self {
        let kind = error.downcast_ref::<std::io::Error>().map(|e| e.kind());
        let code = error.downcast_ref::<ThinStatus>().and_then(|t| t.code());
        let code = code.or_else(|| kind.map(ErrorCode::from_error_kind));
        Self {
            code: code.unwrap_or(ErrorCode::Unknown),
            kind: kind.unwrap_or(ErrorKind::Other),
        }
    }
}

impl metrics::IntoLabels for ExtractedErrorCode {
    fn into_labels(self) -> Vec<metrics::Label> {
        self.into()
    }
}

/// Creates two labels: "ERROR_CODE" and "ERROR_KIND".
impl From<&ExtractedErrorCode> for Vec<metrics::Label> {
    fn from(e: &ExtractedErrorCode) -> Vec<metrics::Label> {
        labels_static(e.code.into(), error_kind_str(e.kind))
    }
}

impl From<ExtractedErrorCode> for Vec<metrics::Label> {
    fn from(e: ExtractedErrorCode) -> Vec<metrics::Label> {
        (&e).into()
    }
}

fn labels_static(code: &'static str, kind: &'static str) -> Vec<metrics::Label> {
    let mut labels = Vec::new();
    labels.push(metrics::Label::from_static_parts("ERROR_CODE", code));
    labels.push(metrics::Label::from_static_parts("ERROR_KIND", kind));
    labels
}

fn error_kind_str(kind: ErrorKind) -> &'static str {
    use std::io::ErrorKind::*;
    match kind {
        NotFound => "NotFound",
        PermissionDenied => "PermissionDenied",
        ConnectionRefused => "ConnectionRefused",
        ConnectionReset => "ConnectionReset",
        HostUnreachable => "HostUnreachable",
        NetworkUnreachable => "NetworkUnreachable",
        ConnectionAborted => "ConnectionAborted",
        NotConnected => "NotConnected",
        AddrInUse => "AddrInUse",
        AddrNotAvailable => "AddrNotAvailable",
        NetworkDown => "NetworkDown",
        BrokenPipe => "BrokenPipe",
        AlreadyExists => "AlreadyExists",
        WouldBlock => "WouldBlock",
        NotADirectory => "NotADirectory",
        IsADirectory => "IsADirectory",
        DirectoryNotEmpty => "DirectoryNotEmpty",
        ReadOnlyFilesystem => "ReadOnlyFilesystem",
        // experimental: FilesystemLoop => "FilesystemLoop",
        StaleNetworkFileHandle => "StaleNetworkFileHandle",
        InvalidInput => "InvalidInput",
        InvalidData => "InvalidData",
        TimedOut => "TimedOut",
        WriteZero => "WriteZero",
        StorageFull => "StorageFull",
        NotSeekable => "NotSeekable",
        QuotaExceeded => "QuotaExceeded",
        FileTooLarge => "FileTooLarge",
        ResourceBusy => "ResourceBusy",
        ExecutableFileBusy => "ExecutableFileBusy",
        Deadlock => "Deadlock",
        CrossesDevices => "CrossesDevices",
        TooManyLinks => "TooManyLinks",
        InvalidFilename => "InvalidFilename",
        ArgumentListTooLong => "ArgumentListTooLong",
        Interrupted => "Interrupted",
        Unsupported => "Unsupported",
        UnexpectedEof => "UnexpectedEof",
        OutOfMemory => "OutOfMemory",
        // experimental: InProgress => "InProgress",
        Other | _ => "Other",
    }
}

/// If `result` is `Cancelled`, converts it into a `()`.
pub fn mask_cancelled(result: Result<(), ThinStatus>) -> Result<(), ThinStatus> {
    match result {
        Err(err) if err.code() == Some(ErrorCode::Cancelled) => {
            tracing::debug!(error = ?err, "Task cancelled");
            Ok(())
        }
        r => r,
    }
}

/// If `result` reports a cancelled `JoinError`, it's converted to `Cancelled`.
/// Any other error (panic) is converted into `Internal`.
pub fn unwrap_join_handle<T>(
    result: Result<Result<T, ThinStatus>, tokio::task::JoinError>,
) -> Result<T, ThinStatus> {
    match result {
        Ok(err) => err,
        Err(join_err) if join_err.is_cancelled() => Err(join_err.error_code(ErrorCode::Cancelled)),
        Err(join_err) => {
            tracing::error!(error = ?join_err, "panicked unexpectedly");
            Err(join_err.error_code(ErrorCode::Internal))
        }
    }
}

/// Awaits `handle` and unwraps its status using `unwrap_join_handle` and `mask_cancelled`.
pub async fn await_loop_result(
    handle: tokio::task::JoinHandle<Result<(), ThinStatus>>,
) -> Result<(), ThinStatus> {
    mask_cancelled(unwrap_join_handle(handle.await))
}

#[macro_export]
macro_rules! check_eq {
    ($left:expr, $right:expr) => {
        if $left != $right {
            let mut status = ThinStatus::builder(ErrorCode::Internal);
            let _ = write!(status, "{} != {}", stringify!($left), stringify!($right));
            Err(status)
        } else {
            Ok(())
        }
    };
}
