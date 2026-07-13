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
