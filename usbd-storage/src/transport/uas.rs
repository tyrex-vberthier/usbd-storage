//! UAS (USB Attached SCSI) IU codec and tag-table.
//!
//! This module provides:
//!
//! * IU codec — [`parse_iu`], [`build_ready_iu`], [`build_status_iu`],
//!   [`build_response_iu`], [`fixed_sense`] — for the four pipe types defined
//!   by the UAS specification.  All functions are pure and panic-free; they
//!   work in `no_std` environments and are host-testable without any USB bus
//!   abstraction.
//!
//! * [`TagTable`] — a fixed-capacity FIFO of in-flight commands, sized for the
//!   32-tag High Speed host queue depth (`qdepth = 32`, tags 1..=32).
//!   `TagTable` is generic-free and `const`-constructible so it can live in
//!   a static or embedded struct.
//!
//! # High Speed sequencing invariant
//!
//! At High Speed (no streams) the Linux `uas` driver:
//!
//! 1. Queues a status-pipe URB for each tag, then sends the Command IU.
//! 2. Waits for the device to send RRDY (read) or WRDY (write) on the status
//!    pipe before submitting the data URB for that tag.
//! 3. Considers a command complete **only** when a Status IU arrives on the
//!    status pipe; data-URB completion alone never finishes a command.
//!
//! Consequence: the device must send exactly one RRDY/WRDY followed by one
//! Status IU per command, in that order.  Sending a Status IU without a
//! preceding RRDY/WRDY (or vice-versa) will leave the host's state machine in
//! an unresolvable state until the 30 s SCSI timeout fires.
//!
//! All IU field offsets and constants in this file come verbatim from the
//! Linux `include/linux/usb/uas.h` header (kernel commit
//! `9716c086c8e8b141d35aa61f2e96a2e83de212a7`).  See
//! `.claude/reference/uas-protocol.md` for the full citation table.

use crate::subclass::scsi::{ScsiCommand, parse_cb};

// ---------------------------------------------------------------------------
// Protocol constants (all from uas.h §1 / §3)
// ---------------------------------------------------------------------------

/// UAS interface protocol code (`USB_PR_UAS`), from `include/linux/usb/storage.h`.
///
/// Forward-declared here; used by the UAS transport engine added in a later
/// substep.
#[allow(dead_code)]
pub(crate) const TRANSPORT_UAS: u8 = 0x62;

/// Host-side queue depth the Linux `uas` driver uses at High Speed.
///
/// Tags are 1-based integers in `1..=UAS_QDEPTH`; up to `UAS_QDEPTH − 2 = 30`
/// may be in flight concurrently (the host reserves two slots internally).
pub const UAS_QDEPTH: usize = 32;

/// IU ID for a Command IU (host → device, command pipe).
const IU_ID_COMMAND: u8 = 0x01;
/// IU ID for a Status (Sense) IU (device → host, status pipe).
const IU_ID_STATUS: u8 = 0x03;
/// IU ID for a Response IU (device → host, status pipe).
const IU_ID_RESPONSE: u8 = 0x04;
/// IU ID for a Task Management IU (host → device, command pipe).
const IU_ID_TASK_MGMT: u8 = 0x05;
/// IU ID for a Read Ready IU (device → host, status pipe).
const IU_ID_READ_READY: u8 = 0x06;
/// IU ID for a Write Ready IU (device → host, status pipe).
const IU_ID_WRITE_READY: u8 = 0x07;

/// On-wire size of a Command IU (CDB ≤ 16 bytes, `len` field == 0).
const COMMAND_IU_LEN: usize = 32;

/// On-wire size of the Status IU header (no sense data).
///
/// A GOOD Status IU with no sense is **exactly 16 bytes** (`f_tcm.c`,
/// `uasp_prepare_status`).
const STATUS_IU_HDR_LEN: usize = 16;

/// On-wire size of a Response IU.
const RESPONSE_IU_LEN: usize = 8;

/// On-wire size of a Read Ready / Write Ready IU.
///
/// RRDY and WRDY share the 4-byte common IU header (`struct iu` in uas.h);
/// `f_tcm.c` sends `sizeof(struct iu)` = 4 bytes for both.
const READY_IU_LEN: usize = 4;

/// Fixed-format sense data length (matches the firmware `RequestSense` payload).
///
/// The UAS spec allows up to 96 bytes of sense (`SCSI_SENSE_BUFFERSIZE`); we
/// always produce 18-byte fixed-format sense and clamp any supplied sense to
/// this length when building a Status IU.
pub(crate) const FIXED_SENSE_LEN: usize = 18;

// ---------------------------------------------------------------------------
// Response codes (uas.h §4)
// ---------------------------------------------------------------------------

/// Response code: TMF not supported (use `RC_TMF_FAILED` for compliance; see
/// protocol note §4).
pub const RC_TMF_NOT_SUPPORTED: u8 = 0x04;
/// Response code: incorrect LUN addressed.
pub const RC_INCORRECT_LUN: u8 = 0x09;
/// Response code: overlapped tag attempted.
pub const RC_OVERLAPPED_TAG: u8 = 0x0a;

// ---------------------------------------------------------------------------
// IU structures
// ---------------------------------------------------------------------------

/// A parsed UAS Command IU.
///
/// Field `lun` is the first byte of the 8-byte SAM LUN field (offset 8 in
/// the IU).  A non-zero LUN is **not** a parse error: the caller must check
/// `lun` and, if it is unsupported, send a Response IU with
/// [`RC_INCORRECT_LUN`].
#[derive(Debug)]
pub struct CommandIu {
    /// Tag (big-endian on the wire, decoded to host order here).
    pub tag: u16,
    /// Task attribute field (`prio_attr`); Linux always sends `UAS_SIMPLE_TAG`
    /// (0).
    pub prio_attr: u8,
    /// Logical Unit Number (byte 8 of the IU; bytes 9–15 are reserved).
    pub lun: u8,
    /// Raw 16-byte CDB (zero-padded for CDBs shorter than 16 bytes).
    pub cdb: [u8; 16],
}

impl CommandIu {
    /// Parse the CDB carried by this Command IU using the shared SCSI CDB
    /// parser.
    ///
    /// Returns the decoded [`ScsiCommand`]; returns
    /// [`ScsiCommand::Unknown`] for unrecognised op-codes — never panics.
    pub fn parse_kind(&self) -> ScsiCommand {
        parse_cb(&self.cdb)
    }
}

/// A parsed UAS Task Management IU.
#[derive(Debug)]
pub struct TaskMgmtIu {
    /// Tag of the Task Management request itself.
    pub tag: u16,
    /// TM function code (`TMF_*` values from uas.h).
    pub function: u8,
    /// Tag of the task being managed.
    pub task_tag: u16,
}

/// The result of a successful [`parse_iu`] call.
#[derive(Debug)]
pub enum IuParse {
    /// A Command IU was received on the command pipe.
    Command(CommandIu),
    /// A Task Management IU was received on the command pipe.
    TaskMgmt(TaskMgmtIu),
}

/// Why a command-pipe packet could not be parsed as an IU.
#[derive(Debug, PartialEq, Eq)]
pub enum IuParseError {
    /// Packet is shorter than the fixed size required for its IU type.
    TooShort {
        /// Expected minimum byte count.
        expected: usize,
        /// Actual byte count received.
        actual: usize,
    },
    /// Byte 0 is not a known IU ID for the command pipe.
    UnknownIuId {
        /// The unrecognised IU ID byte.
        id: u8,
    },
}

impl core::fmt::Display for IuParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(f, "IU too short: expected {expected} bytes, got {actual}")
            }
            Self::UnknownIuId { id } => write!(f, "unknown IU ID: {id:#04x}"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for IuParseError {}

// ---------------------------------------------------------------------------
// IU codec
// ---------------------------------------------------------------------------

/// Parse a raw byte slice received on the **command pipe** into an [`IuParse`].
///
/// Only Command IUs (`IU_ID_COMMAND = 0x01`) and Task Management IUs
/// (`IU_ID_TASK_MGMT = 0x05`) are valid on the command pipe; all other IU IDs
/// are rejected with [`IuParseError::UnknownIuId`].
///
/// A non-zero LUN in a Command IU is **not** a parse error.  The caller must
/// inspect [`CommandIu::lun`] and, if the LUN is unsupported, respond with a
/// Response IU carrying [`RC_INCORRECT_LUN`].
///
/// # Errors
///
/// * [`IuParseError::TooShort`] — if `raw` is shorter than the fixed size for
///   its IU type.
/// * [`IuParseError::UnknownIuId`] — if byte 0 is not `0x01` or `0x05`.
pub fn parse_iu(raw: &[u8]) -> Result<IuParse, IuParseError> {
    let id = raw.first().copied().unwrap_or(0);
    match id {
        IU_ID_COMMAND => {
            if raw.len() < COMMAND_IU_LEN {
                return Err(IuParseError::TooShort {
                    expected: COMMAND_IU_LEN,
                    actual: raw.len(),
                });
            }
            // tag at bytes 2..4, big-endian
            let tag = u16::from_be_bytes([
                raw.get(2).copied().unwrap_or(0),
                raw.get(3).copied().unwrap_or(0),
            ]);
            let prio_attr = raw.get(4).copied().unwrap_or(0);
            // LUN field: 8 bytes at offset 8; we only use the first byte for
            // single-LUN devices.  A non-zero value is returned to the caller,
            // not treated as a parse error.
            let lun = raw.get(8).copied().unwrap_or(0);
            // CDB: 16 bytes at offset 16
            let mut cdb = [0u8; 16];
            if let Some(src) = raw.get(16..32) {
                cdb.copy_from_slice(src);
            }
            Ok(IuParse::Command(CommandIu {
                tag,
                prio_attr,
                lun,
                cdb,
            }))
        }
        IU_ID_TASK_MGMT => {
            // Task Management IU is 16 bytes (uas.h §3.5)
            const TASK_MGMT_IU_LEN: usize = 16;
            if raw.len() < TASK_MGMT_IU_LEN {
                return Err(IuParseError::TooShort {
                    expected: TASK_MGMT_IU_LEN,
                    actual: raw.len(),
                });
            }
            let tag = u16::from_be_bytes([
                raw.get(2).copied().unwrap_or(0),
                raw.get(3).copied().unwrap_or(0),
            ]);
            let function = raw.get(4).copied().unwrap_or(0);
            let task_tag = u16::from_be_bytes([
                raw.get(6).copied().unwrap_or(0),
                raw.get(7).copied().unwrap_or(0),
            ]);
            Ok(IuParse::TaskMgmt(TaskMgmtIu {
                tag,
                function,
                task_tag,
            }))
        }
        id => Err(IuParseError::UnknownIuId { id }),
    }
}

/// Build a 4-byte Read Ready (`read = true`) or Write Ready (`read = false`) IU.
///
/// The IU is sent on the **status pipe** to gate the data phase for the given
/// `tag`.  The host submits the corresponding data URB only after receiving
/// this IU.
pub fn build_ready_iu(read: bool, tag: u16) -> [u8; READY_IU_LEN] {
    let id = if read {
        IU_ID_READ_READY
    } else {
        IU_ID_WRITE_READY
    };
    let tag_bytes = tag.to_be_bytes();
    [id, 0x00, tag_bytes[0], tag_bytes[1]]
}

/// Build a Status IU, with or without sense data.
///
/// Returns the buffer and the number of bytes that should be sent on the wire:
///
/// * `sense` empty → 16 bytes (header only, `len` field == 0).
/// * `sense` non-empty → `STATUS_IU_HDR_LEN + min(sense.len(), FIXED_SENSE_LEN)`
///   bytes; at most [`FIXED_SENSE_LEN`] bytes of sense are copied.
///
/// Field layout (uas.h §3.2):
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0 | 1 | `IU_ID_STATUS` (0x03) |
/// | 1 | 1 | reserved |
/// | 2 | 2 | tag (be16) |
/// | 4 | 2 | status_qual (be16, 0) |
/// | 6 | 1 | SCSI status |
/// | 7 | 7 | reserved |
/// | 14 | 2 | sense length (be16) |
/// | 16 | n | sense data |
pub fn build_status_iu(
    tag: u16,
    status: u8,
    sense: &[u8],
) -> ([u8; STATUS_IU_HDR_LEN + FIXED_SENSE_LEN], usize) {
    let mut buf = [0u8; STATUS_IU_HDR_LEN + FIXED_SENSE_LEN];
    buf[0] = IU_ID_STATUS;
    // byte 1: reserved
    let tag_bytes = tag.to_be_bytes();
    buf[2] = tag_bytes[0];
    buf[3] = tag_bytes[1];
    // bytes 4..6: status_qual (be16) — leave as 0
    buf[6] = status;
    // bytes 7..14: reserved — leave as 0

    let sense_copy_len = sense.len().min(FIXED_SENSE_LEN);
    // sense length field at offset 14 (be16).
    // sense_copy_len ≤ FIXED_SENSE_LEN = 18, so u16 conversion is infallible.
    let sense_len_u16 = u16::try_from(sense_copy_len).unwrap_or(0);
    let sense_len_bytes = sense_len_u16.to_be_bytes();
    buf[14] = sense_len_bytes[0];
    buf[15] = sense_len_bytes[1];

    if sense_copy_len > 0
        && let (Some(dst), Some(src)) = (
            buf.get_mut(STATUS_IU_HDR_LEN..STATUS_IU_HDR_LEN + sense_copy_len),
            sense.get(..sense_copy_len),
        )
    {
        dst.copy_from_slice(src);
    }

    let used = if sense_copy_len == 0 {
        STATUS_IU_HDR_LEN
    } else {
        STATUS_IU_HDR_LEN + sense_copy_len
    };
    (buf, used)
}

/// Build an 8-byte Response IU.
///
/// Response IUs are sent on the **status pipe** in response to Task Management
/// IUs or protocol errors (e.g. incorrect LUN, overlapped tag).
///
/// Field layout (uas.h §3.4):
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0 | 1 | `IU_ID_RESPONSE` (0x04) |
/// | 1 | 1 | reserved |
/// | 2 | 2 | tag (be16) |
/// | 4 | 3 | additional response info (zeros) |
/// | 7 | 1 | response code (`RC_*`) |
pub fn build_response_iu(tag: u16, response_code: u8) -> [u8; RESPONSE_IU_LEN] {
    let tag_bytes = tag.to_be_bytes();
    [
        IU_ID_RESPONSE,
        0x00,
        tag_bytes[0],
        tag_bytes[1],
        0x00,
        0x00,
        0x00,
        response_code,
    ]
}

/// Build an 18-byte fixed-format sense descriptor.
///
/// The sense key, ASC, and ASCQ are written into the standard SPC-4
/// fixed-format positions.  The `VALID` bit (byte 0 bit 7) is not set;
/// `RESPONSE CODE` is `0x70` (current error, fixed format).
///
/// | Byte | Value |
/// |------|-------|
/// | 0 | 0x70 (response code — current, fixed) |
/// | 2 | sense key (bits 3..0) |
/// | 7 | additional sense length = 10 |
/// | 12 | ASC |
/// | 13 | ASCQ |
///
/// All other bytes are zero.
pub fn fixed_sense(key: u8, asc: u8, ascq: u8) -> [u8; FIXED_SENSE_LEN] {
    let mut sense = [0u8; FIXED_SENSE_LEN];
    sense[0] = 0x70; // response code: current error, fixed format
    sense[2] = key & 0x0F;
    sense[7] = 10; // additional sense length = total(18) - 8 = 10
    sense[12] = asc;
    sense[13] = ascq;
    sense
}

// ---------------------------------------------------------------------------
// TagTable
// ---------------------------------------------------------------------------

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
/// carrying [`RC_OVERLAPPED_TAG`].
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
    /// `tag`, `lun`, and `kind` come from a parsed [`CommandIu`].
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
        let head_tag = self.order.get(self.head % UAS_QDEPTH).copied().unwrap_or(0);
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
        if self.len < 2 {
            return None;
        }
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
        let head_tag = self.order.get(self.head % UAS_QDEPTH).copied().unwrap_or(0);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subclass::scsi::ScsiCommand;
    use std::result;

    type TestResult = result::Result<(), Box<dyn std::error::Error>>;

    // -----------------------------------------------------------------------
    // parse_iu tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_command_iu_read10_extracts_tag_lun_cdb() -> TestResult {
        // Given: a 32-byte READ(10) Command IU
        // tag = 0x0001, prio_attr = 0, LUN = 0, CDB = READ(10) LBA=0x1234 len=8
        let mut raw = [0u8; 32];
        raw[0] = IU_ID_COMMAND; // IU ID
        raw[1] = 0x00; // reserved
        raw[2] = 0x00; // tag high
        raw[3] = 0x01; // tag low → tag = 1
        raw[4] = 0x00; // prio_attr
        raw[5] = 0x00; // reserved
        raw[6] = 0x00; // len (additional CDB beyond 16 = 0)
        raw[7] = 0x00; // reserved
        // LUN at bytes 8..16 — all zero for LUN 0
        // CDB at bytes 16..32: READ(10) = 0x28
        raw[16] = 0x28; // READ(10) op-code
        raw[17] = 0x00; // flags
        raw[18] = 0x00; // LBA [31:24]
        raw[19] = 0x00; // LBA [23:16]
        raw[20] = 0x12; // LBA [15:8]
        raw[21] = 0x34; // LBA [7:0]  → LBA = 0x1234
        raw[22] = 0x00; // reserved
        raw[23] = 0x00; // transfer length [15:8]
        raw[24] = 0x08; // transfer length [7:0] → len = 8
        raw[25] = 0x00; // control

        // When: parse_iu is called
        let result = parse_iu(&raw)?;

        // Then: it is a Command IU with the expected fields
        match result {
            IuParse::Command(iu) => {
                assert_eq!(iu.tag, 1, "tag should be 1");
                assert_eq!(iu.lun, 0, "lun should be 0");
                assert_eq!(iu.prio_attr, 0, "prio_attr should be 0");

                // CDB parse yields Read { lba: 0x1234, len: 8 }
                match iu.parse_kind() {
                    #[cfg(not(feature = "extended_addressing"))]
                    ScsiCommand::Read { lba, len } => {
                        assert_eq!(lba, 0x1234, "lba should be 0x1234");
                        assert_eq!(len, 8, "len should be 8");
                    }
                    #[cfg(feature = "extended_addressing")]
                    ScsiCommand::Read { lba, len } => {
                        assert_eq!(lba, 0x1234u64, "lba should be 0x1234");
                        assert_eq!(len, 8u32, "len should be 8");
                    }
                    other => panic!("unexpected ScsiCommand: {:?}", other),
                }
            }
            IuParse::TaskMgmt(_) => panic!("expected Command, got TaskMgmt"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_iu_short_input_returns_too_short() -> TestResult {
        // Given: a 31-byte buffer (one byte short of COMMAND_IU_LEN=32)
        // with IU ID = IU_ID_COMMAND
        let mut raw = [0u8; 31];
        raw[0] = IU_ID_COMMAND;

        // When: parse_iu is called
        let result = parse_iu(&raw);

        // Then: it returns TooShort { expected: 32, actual: 31 }
        assert!(result.is_err(), "expected error for short input");
        match result.unwrap_err() {
            IuParseError::TooShort { expected, actual } => {
                assert_eq!(
                    expected, COMMAND_IU_LEN,
                    "expected length should be COMMAND_IU_LEN (32)"
                );
                assert_eq!(actual, 31, "actual length should be 31");
            }
            e => panic!("unexpected error variant: {:?}", e),
        }
        Ok(())
    }

    #[test]
    fn test_parse_iu_unknown_id_returns_unknown_iu_id() -> TestResult {
        // Given: a buffer with IU ID 0x7F
        let raw = [0x7Fu8; 32];

        // When: parse_iu is called
        let result = parse_iu(&raw);

        // Then: it returns UnknownIuId { id: 0x7F }
        assert!(result.is_err(), "expected error for unknown IU ID");
        match result.unwrap_err() {
            IuParseError::UnknownIuId { id } => {
                assert_eq!(id, 0x7F, "id should be 0x7F");
            }
            e => panic!("unexpected error variant: {:?}", e),
        }
        Ok(())
    }

    #[test]
    fn test_tag_is_big_endian_both_ways() -> TestResult {
        // Given: a Command IU with tag bytes [0x01, 0x00] at offset 2..4
        // (big-endian 0x0100 = decimal 256)
        let mut raw = [0u8; 32];
        raw[0] = IU_ID_COMMAND;
        raw[2] = 0x01; // tag high byte
        raw[3] = 0x00; // tag low byte → tag = 256

        // When: parse_iu is called
        let result = parse_iu(&raw)?;

        // Then: tag is 256
        match result {
            IuParse::Command(iu) => {
                assert_eq!(iu.tag, 256, "tag should be 256 (0x0100 big-endian)");
            }
            IuParse::TaskMgmt(_) => panic!("expected Command"),
        }

        // When: build_status_iu is called with tag=256
        let (buf, _used) = build_status_iu(256, 0x00, &[]);

        // Then: bytes 2..4 are [0x01, 0x00]
        assert_eq!(buf[2], 0x01, "status IU byte 2 should be 0x01");
        assert_eq!(buf[3], 0x00, "status IU byte 3 should be 0x00");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // build_status_iu tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_iu_good_is_16_bytes() -> TestResult {
        // Given: status GOOD (0x00), empty sense
        // When: build_status_iu is called
        let (buf, used) = build_status_iu(1, 0x00, &[]);

        // Then: used length is 16, and sense-length field at bytes 14..16 is 0
        assert_eq!(used, 16, "GOOD status IU should be 16 bytes");
        assert_eq!(buf[0], IU_ID_STATUS, "byte 0 should be IU_ID_STATUS (0x03)");
        assert_eq!(buf[14], 0, "sense length high byte should be 0");
        assert_eq!(buf[15], 0, "sense length low byte should be 0");
        Ok(())
    }

    #[test]
    fn test_status_iu_check_condition_carries_sense() -> TestResult {
        // Given: 18 bytes of sense data, status CHECK_CONDITION (0x02)
        let sense = fixed_sense(0x05, 0x20, 0x00); // sense key 5, ASC 0x20
        assert_eq!(sense.len(), 18, "fixed_sense should produce 18 bytes");

        // When: build_status_iu is called with the sense data
        let (buf, used) = build_status_iu(3, 0x02, &sense);

        // Then: used = 34 (16 header + 18 sense)
        assert_eq!(used, 34, "used should be 34 (16 + 18)");

        // SCSI status at byte 6 should be 0x02 (CHECK_CONDITION)
        assert_eq!(
            buf[6], 0x02,
            "SCSI status byte should be CHECK_CONDITION (0x02)"
        );

        // sense length at bytes 14..16 (be16) should be 18
        let sense_len = u16::from_be_bytes([buf[14], buf[15]]);
        assert_eq!(sense_len, 18, "sense length field should be 18");

        // Sense data at bytes 16..34 should match
        assert_eq!(
            &buf[16..34],
            &sense[..18],
            "sense bytes at offset 16 should match the supplied sense"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // build_ready_iu tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ready_iu_ids_match_spec() -> TestResult {
        // Given: tag = 5

        // When: build_ready_iu(true, 5) — Read Ready
        let rrdy = build_ready_iu(true, 5);

        // Then: 4 bytes, byte 0 == IU_ID_READ_READY (0x06), tag be16 @2..4 == 5
        assert_eq!(rrdy.len(), READY_IU_LEN, "RRDY IU should be 4 bytes");
        assert_eq!(rrdy[0], IU_ID_READ_READY, "RRDY byte 0 should be 0x06");
        assert_eq!(rrdy[1], 0x00, "RRDY byte 1 should be reserved (0x00)");
        let rrdy_tag = u16::from_be_bytes([rrdy[2], rrdy[3]]);
        assert_eq!(rrdy_tag, 5, "RRDY tag should be 5");

        // When: build_ready_iu(false, 5) — Write Ready
        let wrdy = build_ready_iu(false, 5);

        // Then: byte 0 == IU_ID_WRITE_READY (0x07)
        assert_eq!(wrdy[0], IU_ID_WRITE_READY, "WRDY byte 0 should be 0x07");
        let wrdy_tag = u16::from_be_bytes([wrdy[2], wrdy[3]]);
        assert_eq!(wrdy_tag, 5, "WRDY tag should be 5");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // TagTable tests
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Property tests
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// parse_iu never panics on arbitrary input up to 64 bytes.
        #[test]
        fn proptest_parse_iu_never_panics(raw in prop::collection::vec(any::<u8>(), 0..=64)) {
            // Returns Ok or Err — must not panic.
            let _ = parse_iu(&raw);
        }

        /// Any u16 tag survives build_status_iu → byte extraction.
        #[test]
        fn proptest_status_iu_tag_roundtrip(tag in any::<u16>()) {
            let (buf, _used) = build_status_iu(tag, 0x00, &[]);
            let recovered = u16::from_be_bytes([buf[2], buf[3]]);
            prop_assert_eq!(recovered, tag, "tag should roundtrip through build_status_iu");
        }

        /// Any u16 tag survives build_ready_iu for both directions.
        #[test]
        fn proptest_ready_iu_tag_roundtrip(tag in any::<u16>(), read in any::<bool>()) {
            let iu = build_ready_iu(read, tag);
            let recovered = u16::from_be_bytes([iu[2], iu[3]]);
            prop_assert_eq!(recovered, tag, "tag should roundtrip through build_ready_iu");
        }
    }
}
