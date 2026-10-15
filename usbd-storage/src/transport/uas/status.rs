//! The queue of IUs waiting for the status pipe.

use super::UAS_QDEPTH;

/// A pending message for the UAS status pipe.
///
/// These are built by the `Uas` engine and flushed toward the host one at a
/// time via `pump`.  Each variant corresponds to exactly one IU sent on the
/// status pipe.
#[derive(Clone, Copy)]
pub enum StatusMsg {
    /// Read Ready — gates the host's data-IN URB for `tag`.
    ReadReady {
        /// UAS tag of the command.
        tag: u16,
    },
    /// Write Ready — gates the host's data-OUT URB for `tag`.
    WriteReady {
        /// UAS tag of the command.
        tag: u16,
    },
    /// SCSI GOOD status — command completed without error.
    Good {
        /// UAS tag of the command.
        tag: u16,
    },
    /// SCSI CHECK CONDITION status with 18-byte fixed-format sense.
    Check {
        /// UAS tag of the command.
        tag: u16,
        /// Sense key (4 low bits used).
        key: u8,
        /// Additional Sense Code.
        asc: u8,
        /// Additional Sense Code Qualifier.
        ascq: u8,
    },
    /// SCSI TASK SET FULL (0x28) — tag-table-full reply.
    ///
    /// Sent as a Status IU with status byte `SAM_STAT_TASK_SET_FULL` (0x28) and
    /// no sense data.
    TaskSetFull {
        /// UAS tag of the command.
        tag: u16,
    },
    /// UAS Response IU — carries a protocol-level response code (`RC_*`).
    Response {
        /// UAS tag of the command (or the TM request tag).
        tag: u16,
        /// Response code (`RC_TMF_NOT_SUPPORTED`, `RC_INCORRECT_LUN`, …).
        code: u8,
    },
}

/// Status-queue capacity: every in-flight tag plus a margin for protocol
/// messages that arrive before earlier ones drain.
pub(super) const STATUS_QUEUE_CAP: usize = UAS_QDEPTH + 4;

/// Pushing into a full status queue — indicates a logic bug, since the
/// capacity covers every tag plus margin.
#[derive(Debug)]
pub struct StatusQueueFull;

/// Fixed-capacity FIFO ring for pending [`StatusMsg`]s.
///
/// Pure (no USB bus access), host-testable.
pub(super) struct StatusQueue {
    /// Backing storage; `None` means the slot is empty.
    slots: [Option<StatusMsg>; STATUS_QUEUE_CAP],
    /// Index of the oldest slot in `slots`.
    head: usize,
    /// Number of occupied slots.
    len: usize,
}

impl StatusQueue {
    /// Create an empty queue.
    pub(super) const fn new() -> Self {
        // `Option<StatusMsg>` is not `Copy` due to enum, so manual const init.
        Self {
            slots: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ],
            head: 0,
            len: 0,
        }
    }

    /// Enqueue a message at the tail.
    ///
    /// # Errors
    ///
    /// Returns [`StatusQueueFull`] when the queue already holds
    /// `STATUS_QUEUE_CAP` messages — this indicates a logic bug in the caller
    /// since the capacity is sized to exceed the maximum number of in-flight
    /// tags.
    pub(super) fn push(&mut self, msg: StatusMsg) -> Result<(), StatusQueueFull> {
        if self.len >= STATUS_QUEUE_CAP {
            return Err(StatusQueueFull);
        }
        let tail = (self.head + self.len) % STATUS_QUEUE_CAP;
        if let Some(slot) = self.slots.get_mut(tail) {
            *slot = Some(msg);
        }
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// Peek at the head message without removing it.
    ///
    /// Returns `None` if the queue is empty.
    pub(super) fn peek(&self) -> Option<&StatusMsg> {
        if self.len == 0 {
            return None;
        }
        self.slots.get(self.head).and_then(Option::as_ref)
    }

    /// Remove and return the head message.
    ///
    /// Returns `None` if the queue is empty.
    pub(super) fn pop(&mut self) -> Option<StatusMsg> {
        if self.len == 0 {
            return None;
        }
        // `head` is kept below `STATUS_QUEUE_CAP` here.
        let idx = self.head;
        let msg = self.slots.get_mut(idx).and_then(Option::take);
        self.head = (self.head + 1) % STATUS_QUEUE_CAP;
        self.len = self.len.saturating_sub(1);
        msg
    }

    /// Return `true` if no messages are pending.
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discard all pending messages.
    pub(super) fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::super::RC_INCORRECT_LUN;
    use super::*;
    use std::result;

    type TestResult = result::Result<(), Box<dyn std::error::Error>>;

    /// Push N messages into the queue and verify they drain in FIFO order.
    #[test]
    fn test_status_queue_fifo_order_and_capacity() -> TestResult {
        // Given: an empty StatusQueue
        let mut q = StatusQueue::new();
        assert!(q.is_empty(), "queue should start empty");

        // When: push ReadReady(1), WriteReady(2), Good(3), Response(4, 0x09)
        q.push(StatusMsg::ReadReady { tag: 1 }).expect("push 1");
        q.push(StatusMsg::WriteReady { tag: 2 }).expect("push 2");
        q.push(StatusMsg::Good { tag: 3 }).expect("push 3");
        q.push(StatusMsg::Response {
            tag: 4,
            code: RC_INCORRECT_LUN,
        })
        .expect("push 4");

        // Then: peek sees ReadReady(1) without removing it
        assert!(
            matches!(q.peek(), Some(StatusMsg::ReadReady { tag: 1 })),
            "peek should show ReadReady(1)"
        );

        // When: pop all 4 entries
        let m1 = q.pop().expect("pop 1");
        let m2 = q.pop().expect("pop 2");
        let m3 = q.pop().expect("pop 3");
        let m4 = q.pop().expect("pop 4");

        // Then: FIFO order is preserved
        assert!(
            matches!(m1, StatusMsg::ReadReady { tag: 1 }),
            "first pop should be ReadReady(1), got unexpected variant"
        );
        assert!(
            matches!(m2, StatusMsg::WriteReady { tag: 2 }),
            "second pop should be WriteReady(2)"
        );
        assert!(
            matches!(m3, StatusMsg::Good { tag: 3 }),
            "third pop should be Good(3)"
        );
        assert!(
            matches!(m4, StatusMsg::Response { tag: 4, code: 0x09 }),
            "fourth pop should be Response(4, RC_INCORRECT_LUN)"
        );

        // Then: queue is empty after draining
        assert!(
            q.is_empty(),
            "queue should be empty after draining all entries"
        );
        assert!(q.pop().is_none(), "pop on empty queue should return None");
        Ok(())
    }

    /// Filling to STATUS_QUEUE_CAP and then pushing one more returns Full.
    #[test]
    fn test_status_queue_push_at_capacity_returns_full() -> TestResult {
        // Given: a StatusQueue filled to STATUS_QUEUE_CAP
        let mut q = StatusQueue::new();
        for i in 0..STATUS_QUEUE_CAP {
            // Use tag values 1..=STATUS_QUEUE_CAP (u16-safe since cap = 36)
            let tag = u16::try_from(i + 1).unwrap_or(u16::MAX);
            q.push(StatusMsg::Good { tag })
                .expect("push within capacity should succeed");
        }

        // When: one more push is attempted
        let result = q.push(StatusMsg::Good { tag: 0xFFFF });

        // Then: it returns StatusQueueFull (a unit struct — just check it's Err)
        assert!(
            result.is_err(),
            "push into a full queue should return StatusQueueFull"
        );
        // StatusQueueFull is a unit struct; we verify Err(_) is sufficient.
        let StatusQueueFull = result.unwrap_err();
        Ok(())
    }

    /// The ring wraps: a queue filled, half drained and refilled keeps FIFO order.
    #[test]
    fn test_status_queue_wraps_around() -> TestResult {
        let mut q = StatusQueue::new();
        let cap = u16::try_from(STATUS_QUEUE_CAP)?;
        for tag in 0..cap {
            q.push(StatusMsg::Good { tag }).map_err(|_| "push")?;
        }
        for tag in 0..cap / 2 {
            assert!(matches!(q.pop(), Some(StatusMsg::Good { tag: t }) if t == tag));
        }
        for tag in cap..cap + cap / 2 {
            q.push(StatusMsg::Good { tag })
                .map_err(|_| "push after wrap")?;
        }
        for tag in cap / 2..cap + cap / 2 {
            assert!(
                matches!(q.peek(), Some(StatusMsg::Good { tag: t }) if *t == tag),
                "peek in order at {tag}"
            );
            assert!(
                matches!(q.pop(), Some(StatusMsg::Good { tag: t }) if t == tag),
                "pop in order at {tag}"
            );
        }
        assert!(q.is_empty(), "drained");
        Ok(())
    }
}
