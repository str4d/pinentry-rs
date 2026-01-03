//! `pinentry` is a library for interacting with the pinentry binaries available on
//! various platforms.
//!
//! # Examples
//!
//! ## Request passphrase or PIN
//!
//! ```no_run
//! use pinentry::PassphraseInput;
//! use secrecy::SecretString;
//!
//! let passphrase = if let Some(mut input) = PassphraseInput::with_default_binary() {
//!     // pinentry binary is available!
//!     input
//!         .with_description("Enter new passphrase for FooBar")
//!         .with_prompt("Passphrase:")
//!         .with_confirmation("Confirm passphrase:", "Passphrases do not match")
//!         .interact()
//! } else {
//!     // Fall back to some other passphrase entry method.
//!     Ok("a better passphrase than this".to_owned().into())
//! }?;
//! # Ok::<(), pinentry::Error>(())
//! ```
//!
//! ## Ask user for confirmation
//!
//! ```no_run
//! use pinentry::ConfirmationDialog;
//!
//! if let Some(mut input) = ConfirmationDialog::with_default_binary() {
//!     input
//!         .with_ok("Definitely!")
//!         .with_not_ok("No thanks")
//!         .with_cancel("Maybe later")
//!         .confirm("Would you like to play a game?")?;
//! };
//! # Ok::<(), pinentry::Error>(())
//! ```
//!
//! ## Display a message
//!
//! ```no_run
//! use pinentry::MessageDialog;
//!
//! if let Some(mut input) = MessageDialog::with_default_binary() {
//!     input.with_ok("Got it!").show_message("This will be shown with a single button.")?;
//! };
//! # Ok::<(), pinentry::Error>(())
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

use secrecy::SecretString;
use std::ffi::OsStr;
use std::path::PathBuf;

mod assuan;
mod error;

#[cfg(unix)]
pub mod unix;

pub use error::{Error, GpgError};

/// Result type for the `pinentry` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A dialog for requesting a passphrase from the user.
pub struct PassphraseInput<'a> {
    binary: PathBuf,
    required: Option<&'a str>,
    title: Option<&'a str>,
    description: Option<&'a str>,
    error: Option<&'a str>,
    prompt: Option<&'a str>,
    confirmation: Option<(&'a str, &'a str)>,
    ok: Option<&'a str>,
    cancel: Option<&'a str>,
    timeout: Option<u16>,
    #[cfg(unix)]
    unix_options: unix::Options<'a>,
}

impl<'a> PassphraseInput<'a> {
    /// Creates a new PassphraseInput using the binary named `pinentry`.
    ///
    /// Returns `None` if `pinentry` cannot be found in `PATH`.
    pub fn with_default_binary() -> Option<Self> {
        Self::with_binary("pinentry")
    }

    /// Creates a new PassphraseInput using the given path to, or name of, a `pinentry`
    /// binary.
    ///
    /// Returns `None` if:
    /// - A path was provided that does not exist.
    /// - A binary name was provided that cannot be found in `PATH`.
    /// - The binary is found but is not executable.
    pub fn with_binary<T: AsRef<OsStr>>(binary_name: T) -> Option<Self> {
        which::which(binary_name)
            .ok()
            .map(|binary| PassphraseInput {
                binary,
                required: None,
                title: None,
                description: None,
                error: None,
                prompt: None,
                confirmation: None,
                ok: None,
                cancel: None,
                timeout: None,
                #[cfg(unix)]
                unix_options: unix::Options::default(),
            })
    }

    /// Prevents the user from submitting an empty passphrase.
    ///
    /// The provided error text will be displayed if the user submits an empty passphrase.
    /// The dialog will remain open until the user either submits a non-empty passphrase,
    /// or selects the "Cancel" button.
    pub fn required(&mut self, empty_error: &'a str) -> &mut Self {
        self.required = Some(empty_error);
        self
    }

    /// Sets the window title.
    ///
    /// When using this feature you should take care that the window is still identifiable
    /// as the pinentry.
    pub fn with_title(&mut self, title: &'a str) -> &mut Self {
        self.title = Some(title);
        self
    }

    /// Sets the descriptive text to display.
    pub fn with_description(&mut self, description: &'a str) -> &mut Self {
        self.description = Some(description);
        self
    }

    /// Sets the error text to display.
    ///
    /// This is used to display an error message, for example on a second interaction if
    /// the first passphrase was invalid.
    pub fn with_error(&mut self, error: &'a str) -> &mut Self {
        self.error = Some(error);
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

    /// Sets the text for the button signalling confirmation (the "OK" button).
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_ok(&mut self, ok: &'a str) -> &mut Self {
        self.ok = Some(ok);
        self
    }

    /// Sets the text for the button signaling cancellation or disagreement (the "Cancel"
    /// button).
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_cancel(&mut self, cancel: &'a str) -> &mut Self {
        self.cancel = Some(cancel);
        self
    }

    /// Sets the timeout (in seconds) before returning an error.
    pub fn with_timeout(&mut self, timeout: u16) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the UNIX-specific options.
    #[cfg(unix)]
    pub fn with_unix_options(&mut self, options: unix::Options<'a>) -> &mut Self {
        self.unix_options = options;
        self
    }

    /// Asks for a passphrase or PIN.
    pub fn interact(&self) -> Result<SecretString> {
        let mut pinentry = assuan::Connection::open(
            &self.binary,
            #[cfg(unix)]
            self.unix_options,
        )?;

        if let Some(title) = &self.title {
            pinentry.send_request("SETTITLE", Some(title))?;
        }
        if let Some(desc) = &self.description {
            pinentry.send_request("SETDESC", Some(desc))?;
        }
        if let Some(error) = &self.error {
            pinentry.send_request("SETERROR", Some(error))?;
        }
        if let Some(prompt) = &self.prompt {
            pinentry.send_request("SETPROMPT", Some(prompt))?;
        }
        if let Some(ok) = &self.ok {
            pinentry.send_request("SETOK", Some(ok))?;
        }
        if let Some(cancel) = &self.cancel {
            pinentry.send_request("SETCANCEL", Some(cancel))?;
        }
        if let Some((confirmation_prompt, mismatch_error)) = &self.confirmation {
            pinentry.send_request("SETREPEAT", Some(confirmation_prompt))?;
            pinentry.send_request("SETREPEATERROR", Some(mismatch_error))?;
        }
        if let Some(timeout) = self.timeout {
            pinentry.send_request("SETTIMEOUT", Some(&format!("{}", timeout)))?;
        }

        loop {
            match (pinentry.send_request("GETPIN", None)?, self.required) {
                // If the user provides an empty passphrase, GETPIN returns no data.
                (None, None) => return Ok(String::new().into()),
                (Some(passphrase), _) => return Ok(passphrase),
                (_, Some(empty_error)) => {
                    // SETERROR is cleared by GETPIN, so we reset it on each loop.
                    pinentry.send_request("SETERROR", Some(empty_error))?;
                }
            }
        }
    }
}

/// A dialog for requesting a confirmation from the user.
pub struct ConfirmationDialog<'a> {
    binary: PathBuf,
    title: Option<&'a str>,
    ok: Option<&'a str>,
    cancel: Option<&'a str>,
    not_ok: Option<&'a str>,
    timeout: Option<u16>,
    #[cfg(unix)]
    unix_options: unix::Options<'a>,
}

impl<'a> ConfirmationDialog<'a> {
    /// Creates a new ConfirmationDialog using the binary named `pinentry`.
    ///
    /// Returns `None` if `pinentry` cannot be found in `PATH`.
    pub fn with_default_binary() -> Option<Self> {
        Self::with_binary("pinentry")
    }

    /// Creates a new ConfirmationDialog using the given path to, or name of, a `pinentry`
    /// binary.
    ///
    /// Returns `None` if:
    /// - A path was provided that does not exist.
    /// - A binary name was provided that cannot be found in `PATH`.
    /// - The binary is found but is not executable.
    pub fn with_binary<T: AsRef<OsStr>>(binary_name: T) -> Option<Self> {
        which::which(binary_name)
            .ok()
            .map(|binary| ConfirmationDialog {
                binary,
                title: None,
                ok: None,
                cancel: None,
                not_ok: None,
                timeout: None,
                #[cfg(unix)]
                unix_options: unix::Options::default(),
            })
    }

    /// Sets the window title.
    ///
    /// When using this feature you should take care that the window is still identifiable
    /// as the pinentry.
    pub fn with_title(&mut self, title: &'a str) -> &mut Self {
        self.title = Some(title);
        self
    }

    /// Sets the text for the button signalling confirmation (the "OK" button).
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_ok(&mut self, ok: &'a str) -> &mut Self {
        self.ok = Some(ok);
        self
    }

    /// Sets the text for the button signaling cancellation or disagreement (the "Cancel"
    /// button).
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_cancel(&mut self, cancel: &'a str) -> &mut Self {
        self.cancel = Some(cancel);
        self
    }

    /// Enables the third non-affirmative response button (the "Not OK" button).
    ///
    /// This can be used in case three buttons are required (to distinguish between
    /// cancellation and disagreement).
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_not_ok(&mut self, not_ok: &'a str) -> &mut Self {
        self.not_ok = Some(not_ok);
        self
    }

    /// Sets the timeout (in seconds) before returning an error.
    pub fn with_timeout(&mut self, timeout: u16) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the UNIX-specific options.
    #[cfg(unix)]
    pub fn with_unix_options(&mut self, options: unix::Options<'a>) -> &mut Self {
        self.unix_options = options;
        self
    }

    /// Asks for confirmation.
    ///
    /// Returns:
    /// - `Ok(true)` if the "OK" button is selected.
    /// - `Ok(false)` if:
    ///   - the "Cancel" button is selected and the "Not OK" button is disabled.
    ///   - the "Not OK" button is enabled and selected.
    /// - `Err(Error::Cancelled)` if the "Cancel" button is selected and the "Not OK"
    ///   button is enabled.
    pub fn confirm(&self, query: &str) -> Result<bool> {
        let mut pinentry = assuan::Connection::open(
            &self.binary,
            #[cfg(unix)]
            self.unix_options,
        )?;

        pinentry.send_request("SETDESC", Some(query))?;
        if let Some(ok) = &self.ok {
            pinentry.send_request("SETOK", Some(ok))?;
        }
        if let Some(cancel) = &self.cancel {
            pinentry.send_request("SETCANCEL", Some(cancel))?;
        }
        if let Some(not_ok) = &self.not_ok {
            pinentry.send_request("SETNOTOK", Some(not_ok))?;
        }
        if let Some(timeout) = self.timeout {
            pinentry.send_request("SETTIMEOUT", Some(&format!("{}", timeout)))?;
        }

        pinentry
            .send_request("CONFIRM", None)
            .map(|_| true)
            .or_else(|e| match (&e, self.not_ok.is_some()) {
                (Error::Cancelled, false) => Ok(false),
                (Error::Gpg(gpg), true) if gpg.code() == error::GPG_ERR_NOT_CONFIRMED => Ok(false),
                _ => Err(e),
            })
    }
}

/// A dialog for showing a message to the user.
pub struct MessageDialog<'a> {
    binary: PathBuf,
    title: Option<&'a str>,
    ok: Option<&'a str>,
    timeout: Option<u16>,
    #[cfg(unix)]
    unix_options: unix::Options<'a>,
}

impl<'a> MessageDialog<'a> {
    /// Creates a new MessageDialog using the binary named `pinentry`.
    ///
    /// Returns `None` if `pinentry` cannot be found in `PATH`.
    pub fn with_default_binary() -> Option<Self> {
        Self::with_binary("pinentry")
    }

    /// Creates a new MessageDialog using the given path to, or name of, a `pinentry`
    /// binary.
    ///
    /// Returns `None` if:
    /// - A path was provided that does not exist.
    /// - A binary name was provided that cannot be found in `PATH`.
    /// - The binary is found but is not executable.
    pub fn with_binary<T: AsRef<OsStr>>(binary_name: T) -> Option<Self> {
        which::which(binary_name).ok().map(|binary| MessageDialog {
            binary,
            title: None,
            ok: None,
            timeout: None,
            #[cfg(unix)]
            unix_options: unix::Options::default(),
        })
    }

    /// Sets the window title.
    ///
    /// When using this feature you should take care that the window is still identifiable
    /// as the pinentry.
    pub fn with_title(&mut self, title: &'a str) -> &mut Self {
        self.title = Some(title);
        self
    }

    /// Sets the text for the button signalling confirmation (the "OK" button).
    ///
    /// You should use an underscore in the text only if you know that a modern version of
    /// pinentry is used. Modern versions underline the next character after the
    /// underscore and use the first such underlined character as a keyboard accelerator.
    /// Use a double underscore to escape an underscore.
    pub fn with_ok(&mut self, ok: &'a str) -> &mut Self {
        self.ok = Some(ok);
        self
    }

    /// Sets the timeout (in seconds) before returning an error.
    pub fn with_timeout(&mut self, timeout: u16) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the UNIX-specific options.
    #[cfg(unix)]
    pub fn with_unix_options(&mut self, options: unix::Options<'a>) -> &mut Self {
        self.unix_options = options;
        self
    }

    /// Shows a message.
    pub fn show_message(&self, message: &str) -> Result<()> {
        let mut pinentry = assuan::Connection::open(
            &self.binary,
            #[cfg(unix)]
            self.unix_options,
        )?;

        pinentry.send_request("SETDESC", Some(message))?;
        if let Some(ok) = &self.ok {
            pinentry.send_request("SETOK", Some(ok))?;
        }
        if let Some(timeout) = self.timeout {
            pinentry.send_request("SETTIMEOUT", Some(&format!("{}", timeout)))?;
        }

        pinentry.send_request("MESSAGE", None).map(|_| ())
    }
}
