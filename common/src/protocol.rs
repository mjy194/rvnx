use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u16 = 2;
pub const MAX_DATAGRAM: usize = 65_507;
const MAX_CONTROL: usize = 8192;
const MAX_FRAME: usize = MAX_DATAGRAM + 9;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    Register {
        version: u16,
        proxy: String,
        protocol: String,
    },
    Attach {
        ticket: String,
    },
    Ready,
    Error {
        message: String,
    },
    Open {
        ticket: String,
    },
    Cancel {
        ticket: String,
    },
    Ping,
    Pong,
}

#[derive(Debug)]
pub enum Frame {
    Control(Control),
    Datagram { peer: u64, data: Vec<u8> },
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let len = reader.read_u32().await? as usize;
    ensure!(
        (1..=MAX_FRAME).contains(&len),
        "invalid frame length: {len}"
    );
    let kind = reader.read_u8().await?;
    match kind {
        1 => {
            ensure!(len <= MAX_CONTROL + 1, "control frame too large");
            let mut data = vec![0; len - 1];
            reader.read_exact(&mut data).await?;
            Ok(Frame::Control(serde_json::from_slice(&data)?))
        }
        2 => {
            ensure!(len >= 9, "truncated datagram header");
            let peer = reader.read_u64().await?;
            let mut data = vec![0; len - 9];
            reader.read_exact(&mut data).await?;
            Ok(Frame::Datagram { peer, data })
        }
        _ => bail!("unknown frame type: {kind}"),
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    // One contiguous write avoids tiny HTTP/2 DATA frames for each header field.
    let mut bytes = Vec::new();
    match frame {
        Frame::Control(control) => {
            let data = serde_json::to_vec(control)?;
            ensure!(data.len() <= MAX_CONTROL, "control frame too large");
            bytes.extend_from_slice(&((data.len() + 1) as u32).to_be_bytes());
            bytes.push(1);
            bytes.extend_from_slice(&data);
        }
        Frame::Datagram { peer, data } => {
            ensure!(data.len() <= MAX_DATAGRAM, "UDP datagram too large");
            bytes.reserve(data.len() + 13);
            bytes.extend_from_slice(&((data.len() + 9) as u32).to_be_bytes());
            bytes.push(2);
            bytes.extend_from_slice(&peer.to_be_bytes());
            bytes.extend_from_slice(data);
        }
    }
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_control<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Control> {
    match read_frame(reader).await? {
        Frame::Control(control) => Ok(control),
        _ => bail!("expected a control message"),
    }
}

pub async fn send_control<W: AsyncWrite + Unpin>(writer: &mut W, control: Control) -> Result<()> {
    write_frame(writer, &Frame::Control(control)).await
}

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod tests;
