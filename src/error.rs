use std::{fmt, io};

pub(crate) const GPG_ERR_TIMEOUT: u16 = 62;
pub(crate) const GPG_ERR_CANCELED: u16 = 99;
pub(crate) const GPG_ERR_NOT_CONFIRMED: u16 = 114;

/// An uncommon or unexpected GPG error.
///
/// `pinentry` is built on top of Assuan, which inherits all of GPG's error codes. Only
/// some of these error codes are actually used by the common `pinentry` implementations,
/// but it's possible to receive any of them.
#[derive(Debug)]
pub struct GpgError {
    /// The GPG error code.
    ///
    /// See [`err-codes.h.in` from `libgpg-error`] for the mapping from error code to GPG
    /// error type.
    ///
    /// [`err-codes.h.in` from `libgpg-error`]: https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in
    code: u16,

    /// A description of the error, if available.
    ///
    /// See [`err-codes.h.in` from `libgpg-error`] for the likely descriptions.
    ///
    /// [`err-codes.h.in` from `libgpg-error`]: https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in
    description: Option<String>,
}

impl fmt::Display for GpgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code {}", self.code)?;
        if let Some(desc) = &self.description {
            write!(f, ": {}", desc)?;
        }
        Ok(())
    }
}

impl GpgError {
    pub(super) fn new(code: u16, description: Option<String>) -> Self {
        GpgError { code, description }
    }

    /// Returns the GPG code for this error.
    pub fn code(&self) -> u16 {
        self.code
    }
}

/// Errors that may be returned while interacting with `pinentry` binaries.
#[derive(Debug)]
pub enum Error {
    /// The user cancelled the operation.
    Cancelled,
    /// Operation timed out waiting for the user to respond.
    Timeout,

    /// An I/O error occurred while communicating with the `pinentry` binary.
    Io(io::Error),
    /// An uncommon or unexpected GPG error.
    Gpg(GpgError),

    /// The user's input doesn't decode to valid UTF-8.
    Encoding(std::str::Utf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Timeout => write!(f, "Operation timed out"),
            Error::Cancelled => write!(f, "Operation cancelled"),
            Error::Gpg(e) => e.fmt(f),
            Error::Io(e) => e.fmt(f),
            Error::Encoding(e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::Encoding(e)
    }
}

impl Error {
    pub(crate) fn from_parts(code: u16, description: Option<String>) -> Self {
        match code {
            GPG_ERR_TIMEOUT => Error::Timeout,
            GPG_ERR_CANCELED => Error::Cancelled,
            _ => Error::Gpg(GpgError::new(code, description)),
        }
    }
}
