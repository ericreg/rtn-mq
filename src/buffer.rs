use crate::{Error, Result};
use bytes::Bytes;
pub(crate) const PAYLOAD_OVERHEAD: usize = 256;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
pub(crate) struct Budget {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
    pub(crate) wake: Arc<tokio::sync::Notify>,
}
impl Budget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            wake: Arc::new(tokio::sync::Notify::new()),
        })
    }
    pub fn reserve(self: &Arc<Self>, n: usize) -> Result<Permit> {
        let old = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(n).filter(|v| *v <= self.limit)
            })
            .map_err(|_| Error::QueueFull)?;
        self.peak.fetch_max(old + n, Ordering::Relaxed);
        Ok(Permit {
            budget: self.clone(),
            n,
        })
    }
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}
#[derive(Debug)]
pub(crate) struct Permit {
    budget: Arc<Budget>,
    n: usize,
}
impl Permit {
    pub(crate) fn shrink_to(&mut self, n: usize) {
        assert!(n <= self.n);
        self.budget.used.fetch_sub(self.n - n, Ordering::AcqRel);
        self.n = n;
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.n, Ordering::AcqRel);
        self.budget.wake.notify_one();
    }
}
#[derive(Debug)]
struct Payload {
    bytes: Bytes,
    _permits: Vec<Permit>,
}
/// A clone shares immutable storage and every associated memory/queue reservation.
#[derive(Clone, Debug)]
pub struct PayloadLease(Arc<Payload>);
impl PayloadLease {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }
    pub fn len(&self) -> usize {
        self.0.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.bytes.is_empty()
    }
    pub fn copy_payload(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    pub(crate) fn received(bytes: Vec<u8>, permits: Vec<Permit>) -> Self {
        Self(Arc::new(Payload {
            bytes: bytes.into(),
            _permits: permits,
        }))
    }
}
#[derive(Clone, Debug)]
pub struct BufferPool {
    pub(crate) budget: Arc<Budget>,
    max_payload: usize,
}
impl BufferPool {
    pub fn new(max_bytes: usize, max_payload: usize) -> Self {
        Self {
            budget: Budget::new(max_bytes),
            max_payload,
        }
    }
    pub fn resident_bytes(&self) -> usize {
        self.budget.used()
    }
    pub fn copy_from_slice(&self, bytes: &[u8]) -> Result<PayloadLease> {
        if bytes.len() > self.max_payload {
            return Err(Error::MessageTooLarge);
        }
        let p = self.budget.reserve(bytes.len() + PAYLOAD_OVERHEAD)?;
        Ok(PayloadLease::received(bytes.to_vec(), vec![p]))
    }
    /// Takes ownership without copying; the allocation's capacity is charged, not just its length.
    pub fn from_vec(&self, bytes: Vec<u8>) -> Result<PayloadLease> {
        if bytes.len() > self.max_payload {
            return Err(Error::MessageTooLarge);
        }
        let p = self.budget.reserve(bytes.capacity() + PAYLOAD_OVERHEAD)?;
        Ok(PayloadLease::received(bytes, vec![p]))
    }
    pub(crate) fn owns(&self, payload: &PayloadLease) -> bool {
        payload
            .0
            ._permits
            .iter()
            .any(|p| Arc::ptr_eq(&p.budget, &self.budget))
    }
}
