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
        Self { code: ErrorCode::from_error_kind(kind), kind }
    }

    /// Extracts `std::io::Error` and `ThinStatus` from `error`. If there is no `ThinStatus` in
    /// `error` then it converts the `ErrorKind` into `ErrorCode` as well. If there is no available
    /// information, returns `ErrorCode::Unknown` and/or `ErrorKind::Other`.
    pub fn from_anyhow(error: &anyhow::Error) -> Self {
        let kind = error.downcast_ref::<std::io::Error>().map(|e| e.kind());
        let code = error.downcast_ref::<ThinStatus>().and_then(|t| t.code());
        let code = code.or_else(|| kind.map(ErrorCode::from_error_kind));
        Self { code: code.unwrap_or(ErrorCode::Unknown), kind: kind.unwrap_or(ErrorKind::Other) }
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

#[cfg(test)]
mod tests {
    use super::*;
    use metrics::IntoLabels;
    use std::io::Error as IoError;
    use std::num::NonZeroI32;

    #[test]
    fn from_io_keeps_the_kind_and_maps_it_to_a_code() {
        let extracted = ExtractedErrorCode::from_io(&IoError::from(ErrorKind::TimedOut));
        assert_eq!(extracted.kind, ErrorKind::TimedOut);
        assert_eq!(extracted.code, ErrorCode::DeadlineExceeded);
    }

    #[test]
    fn from_anyhow_reads_the_kind_of_a_wrapped_io_error() {
        let err = anyhow::Error::new(IoError::new(ErrorKind::NotFound, "gone"));
        let extracted = ExtractedErrorCode::from_anyhow(&err);
        assert_eq!(extracted.kind, ErrorKind::NotFound);
        assert_eq!(extracted.code, ErrorCode::NotFound);
    }

    #[test]
    fn from_anyhow_prefers_a_thin_status_code_over_the_io_kind() {
        let err = anyhow::Error::new(ThinStatus::builder(ErrorCode::Aborted).build());
        let extracted = ExtractedErrorCode::from_anyhow(&err);
        assert_eq!(extracted.code, ErrorCode::Aborted);
        // No io::Error in the chain, so the kind falls back to `Other`.
        assert_eq!(extracted.kind, ErrorKind::Other);
    }

    #[test]
    fn from_anyhow_falls_back_to_unknown_and_other_when_nothing_matches() {
        let extracted = ExtractedErrorCode::from_anyhow(&anyhow::anyhow!("plain string error"));
        assert_eq!(extracted.code, ErrorCode::Unknown);
        assert_eq!(extracted.kind, ErrorKind::Other);
    }

    #[test]
    fn from_anyhow_falls_back_to_unknown_for_a_thin_status_with_an_unrecognized_code() {
        let weird = ThinStatus::builder(NonZeroI32::new(9999).unwrap()).build();
        let extracted = ExtractedErrorCode::from_anyhow(&anyhow::Error::new(weird));
        assert_eq!(extracted.code, ErrorCode::Unknown);
        assert_eq!(extracted.kind, ErrorKind::Other);
    }

    #[test]
    fn extracted_error_code_becomes_two_ordered_labels() {
        let extracted =
            ExtractedErrorCode { code: ErrorCode::DeadlineExceeded, kind: ErrorKind::TimedOut };
        let labels: Vec<metrics::Label> = (&extracted).into();
        assert_eq!(labels.len(), 2);
        assert_eq!((labels[0].key(), labels[0].value()), ("ERROR_CODE", "DEADLINE_EXCEEDED"));
        assert_eq!((labels[1].key(), labels[1].value()), ("ERROR_KIND", "TimedOut"));

        // The owned conversion and `into_labels()` agree with the borrowed one.
        let owned: Vec<metrics::Label> = extracted.into_labels();
        assert_eq!(owned, labels);
    }

    #[test]
    fn error_kind_str_covers_named_kinds_and_falls_back_to_other() {
        assert_eq!(error_kind_str(ErrorKind::NotFound), "NotFound");
        assert_eq!(error_kind_str(ErrorKind::ConnectionReset), "ConnectionReset");
        assert_eq!(error_kind_str(ErrorKind::WouldBlock), "WouldBlock");
        assert_eq!(error_kind_str(ErrorKind::UnexpectedEof), "UnexpectedEof");
        assert_eq!(error_kind_str(ErrorKind::Other), "Other");
    }

    #[test]
    fn mask_cancelled_swallows_only_the_cancelled_code() {
        assert_eq!(mask_cancelled(Ok(())), Ok(()));
        assert_eq!(mask_cancelled(Err(ThinStatus::builder(ErrorCode::Cancelled).build())), Ok(()));
        let internal = ThinStatus::builder(ErrorCode::Internal).build();
        assert_eq!(mask_cancelled(Err(internal.clone())), Err(internal));
    }

    #[tokio::test]
    async fn unwrap_join_handle_passes_through_a_finished_task_result() {
        let ok = tokio::spawn(async { Ok::<i32, ThinStatus>(7) });
        assert_eq!(unwrap_join_handle(ok.await), Ok(7));

        let failed = tokio::spawn(async {
            Err::<(), ThinStatus>(ThinStatus::builder(ErrorCode::NotFound).build())
        });
        assert_eq!(unwrap_join_handle(failed.await).unwrap_err().code(), Some(ErrorCode::NotFound));
    }

    #[tokio::test]
    async fn unwrap_join_handle_reports_an_aborted_task_as_cancelled() {
        let handle = tokio::spawn(std::future::pending::<Result<(), ThinStatus>>());
        handle.abort();
        let err = unwrap_join_handle(handle.await).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Cancelled));
    }

    #[tokio::test]
    async fn unwrap_join_handle_reports_a_panicked_task_as_internal() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let handle: tokio::task::JoinHandle<Result<(), ThinStatus>> =
            tokio::spawn(async { panic!("boom") });
        let joined = handle.await;
        std::panic::set_hook(prev);

        let err = unwrap_join_handle(joined).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Internal));
    }

    #[tokio::test]
    async fn await_loop_result_masks_an_aborted_loop() {
        let ok = tokio::spawn(async { Ok::<(), ThinStatus>(()) });
        assert_eq!(await_loop_result(ok).await, Ok(()));

        let aborted = tokio::spawn(std::future::pending::<Result<(), ThinStatus>>());
        aborted.abort();
        assert_eq!(await_loop_result(aborted).await, Ok(()));
    }

    #[test]
    fn check_eq_macro_reports_the_stringified_mismatch_as_internal() {
        use std::fmt::Write as _;

        let ok: Result<(), _> = check_eq!(2 + 2, 4);
        assert!(ok.is_ok());

        let err: Result<(), _> = check_eq!(2 + 2, 5);
        let status = err.unwrap_err().build();
        assert_eq!(status.code(), Some(ErrorCode::Internal));
        assert_eq!(status.message(), "2 + 2 != 5");
    }
}
