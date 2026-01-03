//! Unix-specific logic for pinentry binaries.
//!
//! # Examples
//!
//! ## Request passphrase or PIN
//!
//! ```no_run
//! use pinentry::{PassphraseInput, unix};
//! use secrecy::SecretString;
//!
//! let passphrase = if let Some(mut input) = PassphraseInput::with_default_binary() {
//!     // pinentry binary is available!
//!     input
//!         .with_description("Enter new passphrase for FooBar")
//!         .with_prompt("Passphrase:")
//!         .with_confirmation("Confirm passphrase:", "Passphrases do not match")
//!         .with_unix_options(
//!             unix::Options::builder()
//!                 .tty_type("xterm-16color")
//!                 .build()
//!         )
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
//! use pinentry::{ConfirmationDialog, unix};
//!
//! if let Some(mut input) = ConfirmationDialog::with_default_binary() {
//!     input
//!         .with_ok("Definitely!")
//!         .with_not_ok("No thanks")
//!         .with_cancel("Maybe later")
//!         .with_unix_options(
//!             unix::Options::builder()
//!                 .tty_type("xterm-16color")
//!                 .build()
//!         )
//!         .confirm("Would you like to play a game?")?;
//! };
//! # Ok::<(), pinentry::Error>(())
//! ```
//!
//! ## Display a message
//!
//! ```no_run
//! use pinentry::{MessageDialog, unix};
//!
//! if let Some(mut input) = MessageDialog::with_default_binary() {
//!     input.with_ok("Got it!")
//!         .with_unix_options(
//!             unix::Options::builder()
//!                 .tty_type("xterm-16color")
//!                 .build()
//!         )
//!         .show_message("This will be shown with a single button.")?;
//! };
//! # Ok::<(), pinentry::Error>(())
//! ```

use std::{borrow::Cow, process::Command};

/// A builder for [`Options`].
#[derive(Default)]
pub struct OptionsBuilder<'a> {
    inner: Options<'a>,
}

impl<'a> OptionsBuilder<'a> {
    /// Sets the name of the terminal device to use.
    ///
    /// Defaults to `/dev/tty`.
    pub fn tty_name(mut self, tty_name: &'a str) -> Self {
        self.inner.tty_name = Some(tty_name);
        self
    }

    /// Sets the type of the terminal device to use.
    ///
    /// Defaults to the contents of the `TERM` environment variable; if that is unset or
    /// unreadable, defaults to `xterm-256color`.
    pub fn tty_type(mut self, tty_type: &'a str) -> Self {
        self.inner.tty_type = Some(tty_type);
        self
    }

    /// Sets the X11 display to use.
    ///
    /// Defaults to the configured display of the parent process, via its `DISPLAY`
    /// environment variable.
    ///
    /// Passing the empty string `""` into this method will cause the `DISPLAY`
    /// environment variable to be explicitly unset for the pinentry binary.
    ///
    /// This only has an effect if your pinentry binary uses X11.
    pub fn x11_display(mut self, x11_display: &'a str) -> Self {
        self.inner.x11_display = Some(x11_display);
        self
    }

    /// Sets the Wayland display to use.
    ///
    /// Defaults to the configured Wayland display of the parent, via its
    /// `WAYLAND_DISPLAY` environment variable.
    ///
    /// Passing the empty string `""` into this method will cause the `WAYLAND_DISPLAY`
    /// environment variable to be explicitly unset for the pinentry binary.
    ///
    /// This only has an effect if your pinentry binary uses Wayland.
    pub fn wayland_display(mut self, wayland_display: &'a str) -> Self {
        self.inner.wayland_display = Some(wayland_display);
        self
    }

    /// Builds the Unix options.
    pub fn build(self) -> Options<'a> {
        self.inner
    }
}

/// Unix-specific options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options<'a> {
    tty_name: Option<&'a str>,
    tty_type: Option<&'a str>,
    x11_display: Option<&'a str>,
    wayland_display: Option<&'a str>,
}

impl<'a> Options<'a> {
    /// Prepares a new builder for Unix options.
    pub fn builder() -> OptionsBuilder<'a> {
        OptionsBuilder::default()
    }

    pub(crate) fn tty_name(&self) -> &str {
        self.tty_name.unwrap_or("/dev/tty")
    }

    pub(crate) fn tty_type(&self) -> Cow<'a, str> {
        match self.tty_type {
            Some(ty) => Cow::Borrowed(ty),
            None => std::env::var("TERM")
                .map(Cow::Owned)
                .unwrap_or(Cow::Borrowed("xterm-256color")),
        }
    }

    pub(crate) fn set_x11_display(&self, command: &mut Command) {
        if let Some(x11_display) = self.x11_display {
            if x11_display.is_empty() {
                command.env_remove("DISPLAY");
            } else {
                command.env("DISPLAY", x11_display);
            }
        }
    }

    pub(crate) fn set_wayland_display(&self, command: &mut Command) {
        if let Some(wayland_display) = self.wayland_display {
            if wayland_display.is_empty() {
                command.env_remove("WAYLAND_DISPLAY");
            } else {
                command.env("WAYLAND_DISPLAY", wayland_display);
            }
        }
    }
}
