use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

const CHUNK_SIZE: usize = 64 * 1024;
const MAX_REPLY: usize = 4096;
const MAX_SIGNATURE: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum ClamdError {
    #[error("clamd io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("clamd timed out")]
    Timeout,
    #[error("clamd replied: {0}")]
    Reply(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Infected(String),
}

#[derive(Clone, Debug)]
enum Target {
    Tcp(String),
    Unix(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Clamd {
    target: Target,
    timeout: Duration,
}

fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_SIGNATURE)
        .collect()
}

async fn exchange<S>(
    mut stream: S,
    command: &[u8],
    payload: Option<&[u8]>,
) -> Result<String, ClamdError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::with_capacity(command.len() + 2);
    head.push(b'z');
    head.extend_from_slice(command);
    head.push(0);
    stream.write_all(&head).await?;

    if let Some(data) = payload {
        for chunk in data.chunks(CHUNK_SIZE) {
            let size = u32::try_from(chunk.len())
                .map_err(|_| ClamdError::Reply("chunk too large".into()))?;
            stream.write_all(&size.to_be_bytes()).await?;
            stream.write_all(chunk).await?;
        }
        stream.write_all(&0u32.to_be_bytes()).await?;
    }
    stream.flush().await?;

    let mut reply = Vec::with_capacity(64);
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&buf[..n]);
        if reply.contains(&0) || reply.len() >= MAX_REPLY {
            break;
        }
    }
    let end = reply
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(reply.len())
        .min(MAX_REPLY);
    Ok(String::from_utf8_lossy(&reply[..end]).trim().to_string())
}

impl Clamd {
    pub fn new(address: &str, timeout: Duration) -> anyhow::Result<Self> {
        let target = if let Some(path) = address.strip_prefix("unix://") {
            ensure!(!path.is_empty(), "CLAMD_ADDRESS unix path is empty");
            Target::Unix(PathBuf::from(path))
        } else if let Some(host_port) = address.strip_prefix("tcp://") {
            let valid = host_port
                .rsplit_once(':')
                .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
            ensure!(valid, "CLAMD_ADDRESS must look like tcp://host:port");
            Target::Tcp(host_port.to_string())
        } else {
            bail!("CLAMD_ADDRESS must start with tcp:// or unix://");
        };
        Ok(Self { target, timeout })
    }

    async fn command(&self, command: &[u8], payload: Option<&[u8]>) -> Result<String, ClamdError> {
        let run = async {
            match &self.target {
                Target::Tcp(address) => {
                    let stream = TcpStream::connect(address).await?;
                    stream.set_nodelay(true)?;
                    exchange(stream, command, payload).await
                }
                Target::Unix(path) => {
                    exchange(UnixStream::connect(path).await?, command, payload).await
                }
            }
        };
        tokio::time::timeout(self.timeout, run)
            .await
            .map_err(|_| ClamdError::Timeout)?
    }

    pub async fn ping(&self) -> Result<bool, ClamdError> {
        Ok(self.command(b"PING", None).await? == "PONG")
    }

    pub async fn version(&self) -> Result<String, ClamdError> {
        Ok(sanitize(&self.command(b"VERSION", None).await?))
    }

    pub async fn scan(&self, data: &[u8]) -> Result<Verdict, ClamdError> {
        let reply = self.command(b"INSTREAM", Some(data)).await?;
        let result = reply.split_once(": ").map_or(reply.as_str(), |(_, r)| r);
        if result == "OK" {
            return Ok(Verdict::Clean);
        }
        if let Some(signature) = result.strip_suffix(" FOUND") {
            return Ok(Verdict::Infected(sanitize(signature)));
        }
        Err(ClamdError::Reply(sanitize(&reply)))
    }
}
