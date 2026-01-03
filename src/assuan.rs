use std::borrow::Cow;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use log::{debug, info, warn};
use percent_encoding::percent_decode_str;
use secrecy::{ExposeSecret, SecretString};
use wait_timeout::ChildExt;
use zeroize::Zeroize;

use crate::{Error, Result};

const CHILD_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Possible response lines from an Assuan server.
///
/// Reference: https://gnupg.org/documentation/manuals/assuan/Server-responses.html
#[derive(Debug)]
#[allow(dead_code)]
enum Response {
    /// Request was successful.
    Ok(Option<String>),
    /// Request could not be fulfilled. The possible error codes are defined by
    /// `libgpg-error`.
    Err {
        code: u16,
        description: Option<String>,
    },
    /// Informational output by the server, which is still processing the request.
    Information {
        keyword: String,
        status: Option<String>,
    },
    /// Comment line issued only for debugging purposes.
    Comment(String),
    /// Raw data returned to client.
    DataLine(SecretString),
    /// The server needs further information from the client.
    Inquire {
        keyword: String,
        parameters: Option<String>,
    },
}

pub(crate) struct Connection {
    process: Child,
    output: ChildStdin,
    input: BufReader<ChildStdout>,
}

// Percent escape some chars as described here:
// https://gnupg.org/documentation/manuals/assuan/Client-requests.html
fn encode_request(command: &str, parameters: Option<&str>) -> String {
    let cap = command.len() + parameters.map_or(0, |p| p.len() + 10) + 1;
    let mut buf = String::with_capacity(cap);
    buf.push_str(command);
    if let Some(p) = parameters {
        buf.push(' ');
        for c in p.chars() {
            match c {
                '\n' => buf.push_str("%0A"),
                '\r' => buf.push_str("%0D"),
                '%' => buf.push_str("%25"),
                _ => buf.push(c),
            }
        }
    }
    if let Some(b'\\') = buf.as_bytes().last() {
        buf.pop();
        buf.push_str("%5C");
    }
    buf.push('\n');
    assert!(
        buf.as_bytes().len() <= 1000,
        "splitting of long lines yet implemented"
    );
    buf
}

impl Connection {
    pub(crate) fn open(
        name: &Path,
        #[cfg(unix)] unix_options: crate::unix::Options,
    ) -> Result<Self> {
        let mut command = Command::new(name);
        command.stdin(Stdio::piped()).stdout(Stdio::piped());

        #[cfg(unix)]
        {
            unix_options.set_x11_display(&mut command);
            unix_options.set_wayland_display(&mut command);
        }

        let mut process = command.spawn()?;
        let output = process.stdin.take().expect("could open stdin");
        let input = BufReader::new(process.stdout.take().expect("could open stdin"));

        let mut conn = Connection {
            process,
            output,
            input,
        };
        // There is always an initial OK server response
        conn.read_response()?;

        #[cfg(unix)]
        {
            conn.send_request(
                "OPTION",
                Some(&format!("ttyname={}", unix_options.tty_name())),
            )?;
            conn.send_request(
                "OPTION",
                Some(&format!("ttytype={}", unix_options.tty_type())),
            )?;
        }

        Ok(conn)
    }

    pub(crate) fn send_request(
        &mut self,
        command: &str,
        parameters: Option<&str>,
    ) -> Result<Option<SecretString>> {
        let buf = encode_request(command, parameters);
        self.output.write_all(buf.as_bytes())?;
        self.read_response()
    }

    fn read_response(&mut self) -> Result<Option<SecretString>> {
        let mut line = String::new();
        let mut data = None;

        // We loop until we find an OK or ERR response. This is probably sufficient for
        // pinentry, but other Assuan protocols might rely on INQUIRE, which needs
        // intermediate completion states or callbacks.
        loop {
            line.zeroize();
            self.input.read_line(&mut line)?;
            match read::server_response(&line)
                .map(|(_, r)| r)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
            {
                Response::Ok(info) => {
                    if let Some(info) = info {
                        debug!("< OK {}", info);
                    }
                    line.zeroize();
                    return Ok(data);
                }
                Response::Err { code, description } => {
                    line.zeroize();
                    if let Some(mut buf) = data {
                        buf.zeroize();
                    }
                    return Err(Error::from_parts(code, description));
                }
                Response::Comment(comment) => debug!("< # {}", comment),
                Response::DataLine(data_line) => {
                    let buf = data.take();
                    let data_line_decoded =
                        percent_decode_str(data_line.expose_secret()).decode_utf8()?;

                    // Concatenate into a new buffer so we can control allocations.
                    let mut s = String::with_capacity(
                        buf.as_ref()
                            .map(|buf| buf.expose_secret().len())
                            .unwrap_or(0)
                            + data_line_decoded.len(),
                    );
                    if let Some(buf) = buf {
                        s.push_str(buf.expose_secret());
                    }
                    s.push_str(data_line_decoded.as_ref());
                    data = Some(s.into());

                    if let Cow::Owned(mut data_line_decoded) = data_line_decoded {
                        data_line_decoded.zeroize();
                    }
                }
                res => info!("< {:?}", res),
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.send_request("BYE", None);
        match self.process.wait_timeout(CHILD_CLOSE_TIMEOUT) {
            Ok(Some(exit)) if exit.success() => (),
            Ok(Some(exit)) => {
                warn!("pinentry exited with failure: {exit}");
            }
            Ok(None) => {
                warn!("Timeout waiting for pinentry to finish, killing subprocess.");
                let _ = self.process.kill();
            }
            Err(_) => (),
        }
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::complete::{is_not, tag},
        character::complete::{digit1, line_ending},
        combinator::{map, opt},
        sequence::{pair, preceded, terminated},
        IResult, Parser,
    };

    use super::Response;

    fn gpg_error_code(input: &str) -> IResult<&str, u16> {
        map(digit1, |code: &str| {
            let full = code.parse::<u32>().expect("have decimal digits");
            // gpg uses the lowest 16 bits for error codes.
            full as u16
        })
        .parse_complete(input)
    }

    pub(super) fn server_response(input: &str) -> IResult<&str, Response> {
        terminated(
            alt((
                preceded(
                    tag("OK"),
                    map(opt(preceded(tag(" "), is_not("\r\n"))), |params| {
                        Response::Ok(params.map(String::from))
                    }),
                ),
                preceded(
                    tag("ERR "),
                    map(
                        pair(gpg_error_code, opt(preceded(tag(" "), is_not("\r\n")))),
                        |(code, description)| Response::Err {
                            code,
                            description: description.map(String::from),
                        },
                    ),
                ),
                preceded(
                    tag("S "),
                    map(
                        pair(is_not(" \r\n"), opt(preceded(tag(" "), is_not("\r\n")))),
                        |(keyword, status): (&str, _)| Response::Information {
                            keyword: keyword.to_owned(),
                            status: status.map(String::from),
                        },
                    ),
                ),
                preceded(
                    tag("# "),
                    map(is_not("\r\n"), |comment: &str| {
                        Response::Comment(comment.to_owned())
                    }),
                ),
                preceded(
                    tag("D "),
                    map(is_not("\r\n"), |data: &str| {
                        Response::DataLine(data.to_owned().into())
                    }),
                ),
                preceded(
                    tag("INQUIRE "),
                    map(
                        pair(is_not(" \r\n"), opt(preceded(tag(" "), is_not("\r\n")))),
                        |(keyword, parameters): (&str, _)| Response::Inquire {
                            keyword: keyword.to_owned(),
                            parameters: parameters.map(String::from),
                        },
                    ),
                ),
            )),
            line_ending,
        )
        .parse_complete(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding() {
        assert_eq!(encode_request("CMD", None), "CMD\n");
        let pairs = [
            ("bar", " bar\n"),
            ("bar\nbaz", " bar%0Abaz\n"),
            ("bar\rbaz", " bar%0Dbaz\n"),
            ("bar\r\nbaz", " bar%0D%0Abaz\n"),
            ("foo\\", " foo%5C\n"),
        ];
        for (p, want) in &pairs {
            let have = encode_request("", Some(p));
            assert_eq!(&have, want)
        }
    }
}
