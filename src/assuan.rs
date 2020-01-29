use log::{debug, info};
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{ChildStdin, ChildStdout};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Possible response lines from an Assuan server.
///
/// Reference: https://gnupg.org/documentation/manuals/assuan/Server-responses.html
#[derive(Debug)]
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

pub struct Connection {
    output: ChildStdin,
    input: BufReader<ChildStdout>,
}

impl Connection {
    pub fn open(name: &Path) -> Result<Self> {
        let process = Command::new(name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let output = process.stdin.expect("could open stdin");
        let input = BufReader::new(process.stdout.expect("could open stdin"));

        let mut conn = Connection { output, input };
        // There is always an initial OK server response
        conn.read_response()?;

        #[cfg(unix)]
        {
            conn.send_request("OPTION", Some("ttyname=/dev/tty"))?;
            conn.send_request(
                "OPTION",
                Some(&format!(
                    "ttytype={}",
                    std::env::var("TERM")
                        .as_ref()
                        .map(|s| s.as_str())
                        .unwrap_or("xterm-256color")
                )),
            )?;
        }

        Ok(conn)
    }

    pub fn send_request(
        &mut self,
        command: &str,
        parameters: Option<&str>,
    ) -> Result<Option<SecretString>> {
        self.output.write_all(command.as_bytes())?;
        if let Some(p) = parameters {
            self.output.write_all(b" ")?;
            self.output.write_all(p.as_bytes())?;
        }
        self.output.write_all(b"\n")?;
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
                    return Ok(data.map(SecretString::new));
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
                    data = Some(buf.unwrap_or_else(String::new) + data_line.expose_secret());
                }
                res => info!("< {:?}", res),
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.send_request("BYE", None);
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::complete::{is_not, tag},
        character::complete::{digit1, line_ending},
        combinator::{map, opt},
        sequence::{pair, preceded, terminated},
        IResult,
    };
    use secrecy::SecretString;

    use super::Response;

    fn gpg_error_code(input: &str) -> IResult<&str, u16> {
        map(digit1, |code| {
            let full = u32::from_str_radix(code, 10).expect("have decimal digits");
            // gpg uses the lowest 16 bits for error codes.
            full as u16
        })(input)
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
                        Response::DataLine(SecretString::new(data.to_owned()))
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
        )(input)
    }
}
