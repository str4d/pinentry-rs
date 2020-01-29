//! `pinentry` is a library for interacting with the pinentry binaries available on
//! various platforms.
//!
//! # Examples
//!
//! ```no_run
//! use pinentry::PinEntry;
//! use secrecy::SecretString;
//!
//! let passphrase = if let Some(mut input) = PinEntry::with_default_binary() {
//!     // pinentry binary is available!
//!     input
//!         .with_description("Enter new passphrase for FooBar")
//!         .with_prompt("Passphrase:")
//!         .with_confirmation("Confirm passphrase:", "Passphrases do not match")
//!         .get_passphrase()
//!         .map(|p| p.unwrap_or_else(|| SecretString::new(String::new())))
//! } else {
//!     // Fall back to some other passphrase entry method.
//!     Ok(SecretString::new("a better passphrase than this".to_owned()))
//! }?;
//! # Ok::<(), pinentry::Error>(())
//! ```

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

use secrecy::SecretString;
use std::ffi::OsStr;
use std::path::PathBuf;

mod assuan;
mod error;

pub use error::Error;

/// Result type for the `pinentry` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An interface to the `pinentry` binaries available on various platforms.
pub struct PinEntry<'a> {
    binary: PathBuf,
    description: Option<&'a str>,
    prompt: Option<&'a str>,
    confirmation: Option<(&'a str, &'a str)>,
    timeout: Option<u16>,
}

impl<'a> PinEntry<'a> {
    /// Creates a new PinEntry interface using the binary named `pinentry`.
    ///
    /// Returns `None` if `pinentry` cannot be found in `PATH`.
    pub fn with_default_binary() -> Option<Self> {
        Self::with_binary("pinentry".to_owned())
    }

    /// Creates a new PinEntry interface using the given path to, or name of, a `pinentry`
    /// binary.
    ///
    /// Returns `None` if:
    /// - A path was provided that does not exist.
    /// - A binary name was provided that cannot be found in `PATH`.
    /// - The binary is found but is not executable.
    pub fn with_binary<T: AsRef<OsStr>>(binary_name: T) -> Option<Self> {
        which::which(binary_name).ok().map(|binary| PinEntry {
            binary,
            description: None,
            prompt: None,
            confirmation: None,
            timeout: None,
        })
    }

    /// Sets the descriptive text to display.
    pub fn with_description(&mut self, description: &'a str) -> &mut Self {
        self.description = Some(description);
        self
    }

    /// Sets the prompt to show.
    ///
    /// When asking for a passphrase or PIN, this sets the text just before the widget for
    /// passphrase entry.
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_prompt(&mut self, prompt: &'a str) -> &mut Self {
        self.prompt = Some(prompt);
        self
    }

    /// Enables confirmation prompting.
    ///
    /// When asking for a passphrase or PIN, this sets the text just before the widget for
    /// the passphrase confirmation entry.
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_confirmation(
        &mut self,
        confirmation_prompt: &'a str,
        mismatch_error: &'a str,
    ) -> &mut Self {
        self.confirmation = Some((confirmation_prompt, mismatch_error));
        self
    }

    /// Sets the timeout (in seconds) before returning an error.
    pub fn with_timeout(&mut self, timeout: u16) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Asks for a passphrase or PIN.
    ///
    /// Returns `None` if the user provided an empty passphrase or PIN.
    pub fn get_passphrase(&self) -> Result<Option<SecretString>> {
        let mut pinentry = assuan::Connection::open(&self.binary)?;

        if let Some(desc) = &self.description {
            pinentry.send_request("SETDESC", Some(desc))?;
        }
        if let Some(prompt) = &self.prompt {
            pinentry.send_request("SETPROMPT", Some(prompt))?;
        }
        if let Some((confirmation_prompt, mismatch_error)) = &self.confirmation {
            pinentry.send_request("SETREPEAT", Some(confirmation_prompt))?;
            pinentry.send_request("SETREPEATERROR", Some(mismatch_error))?;
        }
        if let Some(timeout) = self.timeout {
            pinentry.send_request("SETTIMEOUT", Some(&format!("{}", timeout)))?;
        }

        let passphrase = pinentry.send_request("GETPIN", None)?;

        Ok(passphrase)
    }
}
