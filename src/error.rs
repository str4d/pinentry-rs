use std::{fmt, io};

/// Assuan is built on top of `libgpg-error`, and inherits all of GPG's error codes.
/// Only some of these error codes are actually used by the common `pinentry`
/// implementations, but it's possible to receive any of them.
#[derive(Debug)]
pub struct GpgError {
    /// The GPG error code.
    ///
    /// See https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in for the
    /// mapping from error code to GPG error type.
    code: u16,

    /// A description of the error, if available.
    ///
    /// See https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in for the
    /// likely descriptions.
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Timeout => write!(f, "Operation timed out"),
            Error::Cancelled => write!(f, "Operation cancelled"),
            Error::Gpg(e) => e.fmt(f),
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    pub(crate) fn from_parts(code: u16, description: Option<String>) -> Self {
        match code {
            62 => Error::Timeout,
            99 => Error::Cancelled,
            _ => Error::Gpg(GpgError::new(code, description)),
        }
    }
}
