//! The table of commands the host has queued, by tag.

use super::UAS_QDEPTH;
use crate::subclass::scsi::ScsiCommand;

/// A single slot in the [`TagTable`].
pub struct TagSlot {
    /// The UAS tag for this command (1-based, 1..=`UAS_QDEPTH`).
    pub tag: u16,
    /// Logical Unit Number from the Command IU.
    pub lun: u8,
    /// The decoded SCSI command kind.
    pub kind: ScsiCommand,
}

/// Error returned by [`TagTable::insert`].
#[derive(Debug, PartialEq, Eq)]
pub enum InsertError {
    /// A command with this tag is already in the table (overlapped tag).
    Overlapped,
    /// The table is full (`UAS_QDEPTH` commands already queued).
    Full,
}

impl core::fmt::Display for InsertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Overlapped => f.write_str("overlapped tag: tag already in table"),
            Self::Full => f.write_str("tag table full"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for InsertError {}

/// Fixed-capacity FIFO of in-flight UAS commands.
///
/// The table tracks up to [`UAS_QDEPTH`] commands (matching the Linux host's
/// High Speed queue depth).  Commands are stored in arrival (FIFO) order via
/// the `order` ring; the head of the FIFO is the oldest outstanding command.
///
/// # Overlap detection
///
/// The Linux host assigns each new command a fresh tag.  If the device
/// receives a Command IU whose tag is already present in the table, the
/// protocol is in an error state; the device must answer with a Response IU
/// carrying [`RC_OVERLAPPED_TAG`](super::RC_OVERLAPPED_TAG).
pub struct TagTable {
    /// Slot storage, indexed by position in the backing array.
    slots: [Option<TagSlot>; UAS_QDEPTH],
    /// Arrival-order FIFO: stores the tag for each command in submission
    /// order.  `order[head % UAS_QDEPTH]` is the oldest tag.
    order: [u16; UAS_QDEPTH],
    /// Index into `order` of the oldest command.
    head: usize,
    /// Number of commands currently in the table.
    len: usize,
}

impl TagTable {
    /// Create an empty `TagTable`.
    pub const fn new() -> Self {
        // `Option<TagSlot>` is not `Copy`, so we must use a manual const init.
        Self {
            slots: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None,
            ],
            order: [0u16; UAS_QDEPTH],
            head: 0,
            len: 0,
        }
    }

    /// Insert a new command into the FIFO.
    ///
    /// `tag`, `lun`, and `kind` come from a parsed [`CommandIu`](super::CommandIu).
    ///
    /// # Errors
    ///
    /// * [`InsertError::Overlapped`] — `tag` is already present in the table.
    /// * [`InsertError::Full`] — the table holds [`UAS_QDEPTH`] commands.
    pub fn insert(&mut self, tag: u16, lun: u8, kind: ScsiCommand) -> Result<(), InsertError> {
        if self.len == UAS_QDEPTH {
            return Err(InsertError::Full);
        }
        // Overlap check: scan all occupied slots.
        for s in self.slots.iter().flatten() {
            if s.tag == tag {
                return Err(InsertError::Overlapped);
            }
        }
        // Find a free slot in the backing array.
        let idx = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(InsertError::Full)?;
        // Safety: idx < UAS_QDEPTH because position() returned Some.
        if let Some(slot_ref) = self.slots.get_mut(idx) {
            *slot_ref = Some(TagSlot { tag, lun, kind });
        }
        // Append tag to the arrival FIFO.
        let fifo_pos = self.head.wrapping_add(self.len) % UAS_QDEPTH;
        if let Some(entry) = self.order.get_mut(fifo_pos) {
            *entry = tag;
        }
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// Return a reference to the oldest queued command (FIFO head).
    ///
    /// Returns `None` if the table is empty.
    pub fn head(&self) -> Option<&TagSlot> {
        if self.len == 0 {
            return None;
        }
        // `head` is kept below `UAS_QDEPTH` by `complete_head`.
        let head_tag = self.order.get(self.head).copied().unwrap_or(0);
        self.slots
            .iter()
            .find_map(|s| s.as_ref().filter(|slot| slot.tag == head_tag))
    }

    /// Return the LBA and block count of the next queued **Read** command
    /// after the head, skipping any non-Read commands.
    ///
    /// Returns `None` if there is no second Read in the queue, or the table
    /// has fewer than two entries.  Used as a cross-command prefetch hint.
    ///
    /// The returned tuple is `(lba, blocks)`.  Under the `extended_addressing`
    /// feature `lba` is a `u64`; without it a `u32`.  This function always
    /// returns `(u32, u32)` regardless of feature flags; with
    /// `extended_addressing` the upper bits of a large LBA are truncated — a
    /// prefetch hint, not an authoritative address.
    pub fn next_read_after_head(&self) -> Option<(u32, u32)> {
        // Walk the FIFO starting at index 1 (skip the head at index 0).
        for offset in 1..self.len {
            let fifo_idx = self.head.wrapping_add(offset) % UAS_QDEPTH;
            let tag = self.order.get(fifo_idx).copied().unwrap_or(0);
            if let Some(slot) = self
                .slots
                .iter()
                .find_map(|s| s.as_ref().filter(|sl| sl.tag == tag))
            {
                match slot.kind {
                    #[cfg(not(feature = "extended_addressing"))]
                    ScsiCommand::Read { lba, len } => {
                        return Some((lba, u32::from(len)));
                    }
                    #[cfg(feature = "extended_addressing")]
                    ScsiCommand::Read { lba, len } => {
                        // Prefetch hint only; truncation of large LBAs is intentional.
                        return Some((u32::try_from(lba).unwrap_or(u32::MAX), len));
                    }
                    _ => continue,
                }
            }
        }
        None
    }

    /// Remove the oldest command from the FIFO (called when the host completes
    /// a command).
    ///
    /// If the table is empty, this is a no-op.
    pub fn complete_head(&mut self) {
        if self.len == 0 {
            return;
        }
        let head_tag = self.order.get(self.head).copied().unwrap_or(0);
        // Free the backing slot.
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(|s| s.tag == head_tag) {
                *slot = None;
                break;
            }
        }
        self.head = self.head.wrapping_add(1) % UAS_QDEPTH;
        self.len = self.len.saturating_sub(1);
    }

    /// Clear all entries from the table.
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.len = 0;
    }

    /// Return the number of commands currently in the table.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the table contains no commands.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for TagTable {
    /// Create an empty `TagTable` (delegates to [`TagTable::new`]).
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::result;

    type TestResult = result::Result<(), Box<dyn std::error::Error>>;

    /// Build a dummy `ScsiCommand::TestUnitReady` for use in table tests.
    fn make_tur() -> ScsiCommand {
        ScsiCommand::TestUnitReady
    }

    /// Build a `ScsiCommand::Read` with the given LBA and block count.
    #[cfg(not(feature = "extended_addressing"))]
    fn make_read(lba: u32, len: u16) -> ScsiCommand {
        ScsiCommand::Read { lba, len }
    }

    #[cfg(feature = "extended_addressing")]
    fn make_read(lba: u32, len: u16) -> ScsiCommand {
        ScsiCommand::Read {
            lba: lba as u64,
            len: u32::from(len),
        }
    }

    #[test]
    fn test_tag_table_fifo_order_and_overlap_rejected() -> TestResult {
        // Given: an empty TagTable
        let mut table = TagTable::new();

        // When: tags 3, 1, 2 are inserted in that order
        table.insert(3, 0, make_tur())?;
        table.insert(1, 0, make_tur())?;
        table.insert(2, 0, make_tur())?;

        // Then: head() is tag 3 (first inserted)
        let head_tag = table.head().map(|s| s.tag);
        assert_eq!(head_tag, Some(3), "head should be tag 3 (oldest)");

        // When: inserting tag 1 again → Overlapped
        let err = table.insert(1, 0, make_tur()).unwrap_err();
        assert_eq!(
            err,
            InsertError::Overlapped,
            "duplicate tag should be Overlapped"
        );

        // When: complete_head × 3
        table.complete_head();
        assert_eq!(
            table.head().map(|s| s.tag),
            Some(1),
            "after removing tag 3, head should be tag 1"
        );
        table.complete_head();
        assert_eq!(
            table.head().map(|s| s.tag),
            Some(2),
            "after removing tag 1, head should be tag 2"
        );
        table.complete_head();
        assert!(
            table.is_empty(),
            "table should be empty after 3 complete_head calls"
        );
        Ok(())
    }

    #[test]
    fn test_tag_table_full_rejects_33rd_insert() -> TestResult {
        // Given: a TagTable filled with UAS_QDEPTH (32) entries
        let mut table = TagTable::new();
        for i in 1..=(UAS_QDEPTH as u16) {
            table.insert(i, 0, make_tur())?;
        }
        assert_eq!(table.len(), UAS_QDEPTH, "table should hold 32 entries");

        // When: a 33rd insert is attempted
        let err = table.insert(33, 0, make_tur()).unwrap_err();

        // Then: Full is returned
        assert_eq!(err, InsertError::Full, "33rd insert should return Full");
        Ok(())
    }

    #[test]
    fn test_next_read_after_head_skips_non_reads() -> TestResult {
        // Given: table with head=Read(lba=0), then TUR, then Read(lba=X)
        let mut table = TagTable::new();
        table.insert(1, 0, make_read(0, 1))?; // head — Read (lba=0)
        table.insert(2, 0, make_tur())?; // non-Read
        table.insert(3, 0, make_read(0x5678, 16))?; // the prefetch hint

        // When: next_read_after_head() is called
        let hint = table.next_read_after_head();

        // Then: hint is (0x5678, 16) — skips the non-Read in slot 2
        assert!(hint.is_some(), "should find a Read after the head");
        let (lba, blocks) = hint.unwrap();
        assert_eq!(lba, 0x5678, "hint lba should be 0x5678");
        assert_eq!(blocks, 16, "hint blocks should be 16");
        Ok(())
    }

    #[test]
    fn test_insert_error_display() -> TestResult {
        assert_eq!(
            InsertError::Overlapped.to_string(),
            "overlapped tag: tag already in table"
        );
        assert_eq!(InsertError::Full.to_string(), "tag table full");
        Ok(())
    }

    #[test]
    fn test_next_read_after_head_with_two_entries() -> TestResult {
        // Given: the head and exactly one Read behind it
        let mut t = TagTable::new();
        t.insert(1, 0, make_tur()).map_err(|_| "insert 1")?;
        t.insert(2, 0, make_read(0x10, 8)).map_err(|_| "insert 2")?;

        // Then: the Read is the hint
        assert_eq!(
            t.next_read_after_head(),
            Some((0x10, 8)),
            "hint with two entries"
        );
        Ok(())
    }

    #[test]
    fn test_completed_tags_free_their_slots() -> TestResult {
        // Given: two commands, both completed
        let mut t = TagTable::new();
        t.insert(1, 0, make_tur()).map_err(|_| "insert 1")?;
        t.insert(2, 0, make_tur()).map_err(|_| "insert 2")?;
        t.complete_head();
        assert_eq!(t.head().map(|s| s.tag), Some(2), "tag 2 is the new head");
        t.complete_head();

        // Then: both tags can be used again
        assert!(t.is_empty(), "table should be empty");
        t.insert(1, 0, make_tur()).map_err(|_| "tag 1 still held")?;
        t.insert(2, 0, make_tur()).map_err(|_| "tag 2 still held")?;
        Ok(())
    }

    #[test]
    fn test_clear_empties_the_table() -> TestResult {
        let mut t = TagTable::new();
        t.insert(1, 0, make_tur()).map_err(|_| "insert 1")?;
        assert!(!t.is_empty(), "one command queued");
        t.clear();
        assert!(t.is_empty(), "cleared");
        assert!(t.head().is_none(), "no head after clear");
        t.insert(1, 0, make_tur())
            .map_err(|_| "tag 1 still held after clear")?;
        Ok(())
    }
}
