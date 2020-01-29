#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

mod assuan;
mod error;

pub use error::Error;

/// Result type for the `pinentry` crate.
pub type Result<T> = std::result::Result<T, Error>;
