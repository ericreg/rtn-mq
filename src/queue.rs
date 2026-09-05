//! One producer and one consumer, backed by rtrb. Notifications park the consumer;
//! ring push/pop retain rtrb's nonblocking behavior. Neither endpoint is Clone.
use crate::buffer::Permit;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;
struct Shared {
    ready: Notify,
    sender_closed: AtomicBool,
    receiver_closed: AtomicBool,
    _memory: Permit,
}
pub(crate) struct Sender<T> {
    producer: rtrb::Producer<T>,
    shared: Arc<Shared>,
}
pub(crate) struct Receiver<T> {
    consumer: rtrb::Consumer<T>,
    shared: Arc<Shared>,
}
pub(crate) fn channel<T>(capacity: usize, memory: Permit) -> (Sender<T>, Receiver<T>) {
    let (producer, consumer) = rtrb::RingBuffer::new(capacity);
    let shared = Arc::new(Shared {
        ready: Notify::new(),
        sender_closed: AtomicBool::new(false),
        receiver_closed: AtomicBool::new(false),
        _memory: memory,
    });
    (
        Sender {
            producer,
            shared: shared.clone(),
        },
        Receiver { consumer, shared },
    )
}
impl<T> Sender<T> {
    pub fn try_send(&mut self, value: T) -> std::result::Result<(), T> {
        if self.is_closed() {
            return Err(value);
        }
        self.producer
            .push(value)
            .map_err(|rtrb::PushError::Full(v)| v)?;
        self.shared.ready.notify_one();
        Ok(())
    }
    pub fn is_closed(&self) -> bool {
        self.shared.receiver_closed.load(Ordering::Acquire)
    }
}
impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.shared.sender_closed.store(true, Ordering::Release);
        self.shared.ready.notify_one();
    }
}
impl<T> Receiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            let notified = self.shared.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Ok(value) = self.consumer.pop() {
                return Some(value);
            }
            if self.shared.sender_closed.load(Ordering::Acquire) {
                return self.consumer.pop().ok();
            }
            notified.await;
        }
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.shared.receiver_closed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Budget;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wraparound_cancellation_and_close_do_not_lose_wakeups() {
        let budget = Budget::new(4096);
        let (mut tx, mut rx) = channel(1, budget.reserve(4096).unwrap());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), rx.recv())
                .await
                .is_err()
        );
        let writer = tokio::spawn(async move {
            for mut value in 0..10000 {
                loop {
                    match tx.try_send(value) {
                        Ok(()) => break,
                        Err(v) => {
                            value = v;
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for expected in 0..10000 {
                assert_eq!(rx.recv().await, Some(expected));
            }
            assert_eq!(rx.recv().await, None);
        })
        .await
        .unwrap();
        writer.await.unwrap();
        assert_eq!(budget.used(), 4096);
        drop(rx);
        assert_eq!(budget.used(), 0);
    }
    #[tokio::test]
    async fn full_queue_never_overwrites_and_close_releases_queued_values() {
        let budget = Budget::new(128);
        let (mut tx, mut rx) = channel(1, budget.reserve(128).unwrap());
        tx.try_send(1).unwrap();
        assert_eq!(tx.try_send(2), Err(2));
        assert_eq!(rx.recv().await, Some(1));
        drop(rx);
        assert_eq!(tx.try_send(3), Err(3));
        drop(tx);
        assert_eq!(budget.used(), 0);
    }
}
