use crate::{
    DeliveryMode, Error, Result, Topic,
    auth::{MAX_CERT, version},
    cbor::{Reader, Writer, canonical},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub(crate) const MAX_METADATA: usize = 16 * 1024;
pub(crate) type Id = [u8; 16];
pub(crate) const HELLO: u8 = 1;
pub(crate) const READY: u8 = 2;
pub(crate) const DATA: u8 = 7;

#[derive(Debug)]
pub(crate) struct Header {
    pub kind: u8,
    pub metadata: usize,
    pub payload: usize,
}
impl Header {
    pub fn encode(&self) -> Result<[u8; 12]> {
        let body = u32::try_from(
            self.metadata
                .checked_add(self.payload)
                .ok_or(Error::MessageTooLarge)?,
        )
        .map_err(|_| Error::MessageTooLarge)?;
        let mut b = [0; 12];
        b[..4].copy_from_slice(&body.to_be_bytes());
        b[4] = self.kind;
        b[8..].copy_from_slice(&(self.metadata as u32).to_be_bytes());
        Ok(b)
    }
    pub fn decode(b: [u8; 12], max_payload: usize) -> Result<Self> {
        let body = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        let metadata = u32::from_be_bytes(b[8..].try_into().unwrap()) as usize;
        if b[5..8] != [0, 0, 0] || !(1..=12).contains(&b[4]) || metadata > body {
            return Err(Error::Protocol("frame prefix"));
        }
        let payload = body - metadata;
        if metadata > MAX_METADATA || payload > max_payload {
            return Err(Error::MessageTooLarge);
        }
        if b[4] != DATA && payload != 0 {
            return Err(Error::Protocol("control payload"));
        }
        Ok(Self {
            kind: b[4],
            metadata,
            payload,
        })
    }
}
pub(crate) async fn read_header<R: AsyncRead + Unpin>(
    r: &mut R,
    max_payload: usize,
) -> Result<Option<Header>> {
    let mut b = [0; 12];
    if r.read(&mut b[..1]).await? == 0 {
        return Ok(None);
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        r.read_exact(&mut b[1..]),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(Some(Header::decode(b, max_payload)?))
}
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: u8,
    metadata: &[u8],
    payload: &[u8],
) -> Result<()> {
    if metadata.len() > MAX_METADATA {
        return Err(Error::MessageTooLarge);
    }
    w.write_all(
        &Header {
            kind,
            metadata: metadata.len(),
            payload: payload.len(),
        }
        .encode()?,
    )
    .await?;
    w.write_all(metadata).await?;
    w.write_all(payload).await?;
    Ok(())
}
pub(crate) fn hello(
    cert: &[u8],
    nonce: Id,
    max_payload: usize,
    max_topics: usize,
    window_secs: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(6);
    w.u(1);
    w.bytes(cert);
    w.bytes(&nonce);
    w.u(max_payload as u64);
    w.u(max_topics as u64);
    w.u(window_secs);
    w.finish()
}
pub(crate) struct Hello {
    pub cert: Vec<u8>,
    pub nonce: Id,
    pub max_payload: usize,
    pub max_topics: usize,
    pub window_secs: u64,
}
pub(crate) fn parse_hello(b: &[u8]) -> Result<Hello> {
    let mut r = Reader::new(b);
    r.array(6)?;
    version(r.u()?)?;
    let cert = r.bytes(MAX_CERT)?.to_vec();
    let nonce = r.fixed()?;
    let max_payload = usize::try_from(r.u()?).map_err(|_| Error::MessageTooLarge)?;
    let max_topics = usize::try_from(r.u()?).map_err(|_| Error::MessageTooLarge)?;
    let window_secs = r.u()?;
    r.end()?;
    if max_payload == 0
        || max_payload > 1024 * 1024
        || max_topics == 0
        || max_topics > 256
        || window_secs == 0
        || window_secs > 300
    {
        return Err(Error::Protocol("HELLO limits"));
    }
    canonical(
        b,
        &hello(&cert, nonce, max_payload, max_topics, window_secs),
    )?;
    Ok(Hello {
        cert,
        nonce,
        max_payload,
        max_topics,
        window_secs,
    })
}
pub(crate) fn ready(local: Id, remote: Id) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(3);
    w.u(1);
    w.bytes(&local);
    w.bytes(&remote);
    w.finish()
}
#[derive(Debug, Clone)]
pub(crate) enum Control {
    Subscribe {
        topic: Topic,
        sub: Id,
        mode: DeliveryMode,
    },
    Suback {
        topic: Topic,
        sub: Id,
        code: u64,
    },
    Unsubscribe {
        topic: Topic,
        sub: Id,
    },
    Credit {
        topic: Topic,
        sub: Id,
        bytes: usize,
    },
    RequestCredit {
        topic: Topic,
        sub: Id,
        bytes: usize,
    },
    Outcome {
        topic: Topic,
        sub: Id,
        epoch: Id,
        sequence: u64,
        code: u64,
    },
    Error(u64),
    Goodbye,
}
impl Control {
    pub fn encode(&self, session: Id) -> (u8, Vec<u8>) {
        let mut w = Writer::new();
        let (kind, len) = match self {
            Self::Subscribe { .. } => (3, 5),
            Self::Suback { .. } => (4, 5),
            Self::Unsubscribe { .. } => (5, 4),
            Self::Credit { .. } | Self::RequestCredit { .. } => (6, 6),
            Self::Outcome { code: 0, .. } => (8, 7),
            Self::Outcome { .. } => (9, 7),
            Self::Error(_) => (11, 3),
            Self::Goodbye => (12, 2),
        };
        w.array(len);
        w.u(1);
        w.bytes(&session);
        match self {
            Self::Subscribe { topic, sub, mode } => {
                w.text(topic.as_str());
                w.bytes(sub);
                w.u(mode.number());
            }
            Self::Suback { topic, sub, code } => {
                w.text(topic.as_str());
                w.bytes(sub);
                w.u(*code);
            }
            Self::Unsubscribe { topic, sub } => {
                w.text(topic.as_str());
                w.bytes(sub);
            }
            Self::RequestCredit { topic, sub, bytes } => {
                w.text(topic.as_str());
                w.bytes(sub);
                w.u(0);
                w.u(*bytes as u64);
            }
            Self::Credit { topic, sub, bytes } => {
                w.text(topic.as_str());
                w.bytes(sub);
                w.u(1);
                w.u(*bytes as u64);
            }
            Self::Outcome {
                topic,
                sub,
                epoch,
                sequence,
                code,
            } => {
                w.text(topic.as_str());
                w.bytes(sub);
                w.bytes(epoch);
                w.u(*sequence);
                w.u(*code);
            }
            Self::Error(code) => w.u(*code),
            Self::Goodbye => {}
        }
        (kind, w.finish())
    }
    pub fn decode(kind: u8, b: &[u8], session: Id) -> Result<Self> {
        let len = match kind {
            3 | 4 => 5,
            5 => 4,
            6 => 6,
            8 | 9 => 7,
            11 => 3,
            12 => 2,
            _ => return Err(Error::Protocol("control frame type")),
        };
        let mut r = Reader::new(b);
        r.array(len)?;
        version(r.u()?)?;
        if r.fixed::<16>()? != session {
            return Err(Error::Protocol("session mismatch"));
        }
        let c = match kind {
            3 => Self::Subscribe {
                topic: Topic::new(r.text(256)?)?,
                sub: r.fixed()?,
                mode: DeliveryMode::decode(r.u()?)?,
            },
            4 => Self::Suback {
                topic: Topic::new(r.text(256)?)?,
                sub: r.fixed()?,
                code: r.u()?,
            },
            5 => Self::Unsubscribe {
                topic: Topic::new(r.text(256)?)?,
                sub: r.fixed()?,
            },
            6 => {
                let topic = Topic::new(r.text(256)?)?;
                let sub = r.fixed()?;
                let slots = r.u()?;
                let bytes = usize::try_from(r.u()?).map_err(|_| Error::MessageTooLarge)?;
                match slots {
                    0 => Self::RequestCredit { topic, sub, bytes },
                    1 => Self::Credit { topic, sub, bytes },
                    _ => return Err(Error::Protocol("credit slots")),
                }
            }
            8 | 9 => {
                let topic = Topic::new(r.text(256)?)?;
                let sub = r.fixed()?;
                let epoch = r.fixed()?;
                let sequence = r.u()?;
                let code = r.u()?;
                if (kind == 8 && code != 0) || (kind == 9 && !(1..=2).contains(&code)) {
                    return Err(Error::Protocol("outcome code"));
                }
                Self::Outcome {
                    topic,
                    sub,
                    epoch,
                    sequence,
                    code,
                }
            }
            11 => Self::Error(r.u()?),
            12 => Self::Goodbye,
            _ => unreachable!(),
        };
        r.end()?;
        canonical(b, &c.encode(session).1)?;
        Ok(c)
    }
}
pub(crate) fn data(session: Id, sub: Id, envelope: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(4);
    w.u(1);
    w.bytes(&session);
    w.bytes(&sub);
    w.bytes(envelope);
    w.finish()
}
pub(crate) fn parse_data(b: &[u8], expected: Id) -> Result<(Id, Vec<u8>)> {
    let mut r = Reader::new(b);
    r.array(4)?;
    version(r.u()?)?;
    if r.fixed::<16>()? != expected {
        return Err(Error::Protocol("DATA session"));
    }
    let sub = r.fixed()?;
    let envelope = r.bytes(4096)?.to_vec();
    r.end()?;
    canonical(b, &data(expected, sub, &envelope))?;
    Ok((sub, envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn arbitrary_chunk_splits_and_truncation_at_every_boundary() {
        let (kind, metadata) = Control::Credit {
            topic: Topic::new("jobs").unwrap(),
            sub: [2; 16],
            bytes: 4096,
        }
        .encode([1; 16]);
        let header = Header {
            kind,
            metadata: metadata.len(),
            payload: 0,
        }
        .encode()
        .unwrap();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&metadata);
        for split in 1..frame.len() {
            let (mut w, mut r) = tokio::io::duplex(1);
            let bytes = frame.clone();
            let writer = tokio::spawn(async move {
                w.write_all(&bytes[..split]).await.unwrap();
                tokio::task::yield_now().await;
                w.write_all(&bytes[split..]).await.unwrap();
            });
            let h = read_header(&mut r, 1024).await.unwrap().unwrap();
            let mut body = vec![0; h.metadata];
            r.read_exact(&mut body).await.unwrap();
            Control::decode(h.kind, &body, [1; 16]).unwrap();
            writer.await.unwrap();
        }
        for n in 1..frame.len() {
            let mut input = &frame[..n];
            let result = async {
                let h = read_header(&mut input, 1024).await?.unwrap();
                let mut bytes = vec![0; h.metadata];
                input.read_exact(&mut bytes).await?;
                Ok::<(), Error>(())
            }
            .await;
            assert!(result.is_err(), "prefix {n}");
        }
    }
    #[test]
    fn validates_lengths_types_flags_and_session_before_body_allocation() {
        let valid = Header {
            kind: DATA,
            metadata: 64,
            payload: 100,
        }
        .encode()
        .unwrap();
        assert!(Header::decode(valid, 99).is_err());
        for index in [5, 6, 7] {
            let mut bad = valid;
            bad[index] = 1;
            assert!(Header::decode(bad, 100).is_err());
        }
        let mut bad = valid;
        bad[8..].copy_from_slice(&1000u32.to_be_bytes());
        assert!(Header::decode(bad, 100).is_err());
        let (kind, b) = Control::Goodbye.encode([1; 16]);
        assert!(Control::decode(kind, &b, [2; 16]).is_err());
        let mut b = b;
        b.push(0);
        assert!(Control::decode(kind, &b, [1; 16]).is_err());
    }
}
