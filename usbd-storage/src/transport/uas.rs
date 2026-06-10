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

#[cfg(feature = "transfer")]
use crate::fmt::trace;
use crate::subclass::scsi::{ScsiCommand, parse_cb};
#[cfg(feature = "transfer")]
use crate::transfer::TransferBus;
#[cfg(feature = "transfer")]
use usb_device::UsbError;
#[cfg(feature = "transfer")]
use usb_device::bus::{UsbBus, UsbBusAllocator};
#[cfg(feature = "transfer")]
use usb_device::endpoint::{Endpoint, EndpointAddress, In, Out};

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
/// Field `lun` is the single-level LUN collapsed from the 8-byte SAM LUN
/// field at IU offset 8 (see the field doc).  A non-zero LUN is **not** a
/// parse error: the caller must check `lun` and, if it is unsupported, send
/// a Response IU with [`RC_INCORRECT_LUN`].
#[derive(Debug)]
pub struct CommandIu {
    /// Tag (big-endian on the wire, decoded to host order here).
    pub tag: u16,
    /// Task attribute field (`prio_attr`); Linux always sends `UAS_SIMPLE_TAG`
    /// (0).
    pub prio_attr: u8,
    /// Single-level Logical Unit Number (byte 9 of the IU's 8-byte SAM
    /// peripheral-addressing LUN field; byte 8 and bytes 10–15 must be 0).
    /// Any other encoding collapses to `u8::MAX` so single-LUN callers
    /// reject it via the incorrect-LUN path.
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
            // LUN field: 8 bytes at offset 8, SAM peripheral addressing.
            // Byte 8 is the address-method/bus byte (0 for a single-level
            // LUN < 256); **byte 9 carries the LUN number**. Linux fills it
            // via int_to_scsilun(), so LUN 1 arrives as [0x00, 0x01, 0, ..]
            // (HW-observed 2026-06-11; reading byte 8 made every LUN parse
            // as 0 and the host attached phantom LUNs 1-4). Any encoding
            // other than a clean single-level LUN collapses to a non-zero
            // sentinel so single-LUN callers reject it. A non-zero value is
            // returned to the caller, not treated as a parse error.
            let lun_field_clean = raw.get(8).copied().unwrap_or(0) == 0
                && raw
                    .get(10..16)
                    .is_some_and(|rest| rest.iter().all(|b| *b == 0));
            let lun = if lun_field_clean {
                raw.get(9).copied().unwrap_or(0)
            } else {
                u8::MAX
            };
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
// UAS engine (feature = "transfer" / "uas")
// ---------------------------------------------------------------------------

/// A pending message for the UAS status pipe.
///
/// These are built by the `Uas` engine and flushed toward the host one at a
/// time via `pump`.  Each variant corresponds to exactly one IU sent on the
/// status pipe.
#[cfg(feature = "transfer")]
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
#[cfg(feature = "transfer")]
const STATUS_QUEUE_CAP: usize = UAS_QDEPTH + 4;

/// Pushing into a full status queue — indicates a logic bug, since the
/// capacity covers every tag plus margin.
#[cfg(feature = "transfer")]
#[derive(Debug)]
pub struct StatusQueueFull;

/// Fixed-capacity FIFO ring for pending [`StatusMsg`]s.
///
/// Pure (no USB bus access), host-testable.
#[cfg(feature = "transfer")]
struct StatusQueue {
    /// Backing storage; `None` means the slot is empty.
    slots: [Option<StatusMsg>; STATUS_QUEUE_CAP],
    /// Index of the oldest slot in `slots`.
    head: usize,
    /// Number of occupied slots.
    len: usize,
}

#[cfg(feature = "transfer")]
impl StatusQueue {
    /// Create an empty queue.
    const fn new() -> Self {
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
    fn push(&mut self, msg: StatusMsg) -> Result<(), StatusQueueFull> {
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
    fn peek(&self) -> Option<&StatusMsg> {
        if self.len == 0 {
            return None;
        }
        self.slots
            .get(self.head % STATUS_QUEUE_CAP)
            .and_then(Option::as_ref)
    }

    /// Remove and return the head message.
    ///
    /// Returns `None` if the queue is empty.
    fn pop(&mut self) -> Option<StatusMsg> {
        if self.len == 0 {
            return None;
        }
        let idx = self.head % STATUS_QUEUE_CAP;
        let msg = self.slots.get_mut(idx).and_then(Option::take);
        self.head = (self.head + 1) % STATUS_QUEUE_CAP;
        self.len = self.len.saturating_sub(1);
        msg
    }

    /// Return `true` if no messages are pending.
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discard all pending messages.
    fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.len = 0;
    }
}

/// UAS transport engine.
///
/// `Uas` owns the two UAS-exclusive bulk endpoints (command OUT, status IN) and
/// stores the addresses of the shared data endpoints (bulk IN/OUT) that are also
/// used by [`BulkOnly`] in alt-0.
///
/// # Ordering invariant
///
/// RRDY/WRDY messages are enqueued in the same order their data phases are
/// submitted on the shared data pipes.  Because both the status queue and the
/// USB bulk pipe are FIFOs, the host observes ready-IU order == data-submit
/// order, satisfying the HS sequencing rule (§7 of the protocol reference).
///
/// [`BulkOnly`]: crate::transport::bbb::BulkOnly
#[cfg(feature = "transfer")]
pub struct Uas<'alloc, Bus: UsbBus> {
    /// Command pipe: bulk OUT, host → device.
    cmd_ep: Endpoint<'alloc, Bus, Out>,
    /// Status pipe: bulk IN, device → host.
    status_ep: Endpoint<'alloc, Bus, In>,
    /// Address of the shared data-IN endpoint (reuses BOT bulk IN).
    data_in: EndpointAddress,
    /// Address of the shared data-OUT endpoint (reuses BOT bulk OUT).
    data_out: EndpointAddress,
    /// In-flight command tag table.
    pub table: TagTable,
    /// Pending status-pipe messages.
    status_q: StatusQueue,
}

#[cfg(feature = "transfer")]
impl<'alloc, Bus: UsbBus> Uas<'alloc, Bus> {
    /// Allocate the UAS-exclusive endpoints and create the engine.
    ///
    /// `data_in` and `data_out` are the endpoint addresses of the BOT bulk
    /// endpoints that are shared with the alt-0 setting; they are stored here
    /// so `pump` can drive data-phase transfers on them.
    pub(crate) fn new(
        alloc: &'alloc UsbBusAllocator<Bus>,
        packet_size: u16,
        data_in: EndpointAddress,
        data_out: EndpointAddress,
    ) -> Self {
        Self {
            // Command pipe: host sends Command IUs / Task Mgmt IUs here.
            cmd_ep: alloc.bulk(packet_size),
            // Status pipe: device sends RRDY/WRDY/Status/Response IUs here.
            status_ep: alloc.bulk(packet_size),
            data_in,
            data_out,
            table: TagTable::new(),
            status_q: StatusQueue::new(),
        }
    }

    /// Drive the UAS engine one step.
    ///
    /// * Reads one command-pipe packet and dispatches it:
    ///   - Command IU, LUN 0 → insert into the tag table; on collision push
    ///     `Response { RC_OVERLAPPED_TAG }`; on full push `TaskSetFull`.
    ///   - Command IU, LUN ≠ 0 → push `Response { RC_INCORRECT_LUN }`.
    ///   - Task Management IU → push `Response { RC_TMF_NOT_SUPPORTED }`.
    ///   - Parse error → logged at TRACE level, packet dropped.
    /// * Drains pending status-queue entries onto the status pipe until the
    ///   queue is empty or the endpoint reports `WouldBlock`.
    pub fn pump(&mut self) {
        self.pump_cmd_pipe();
        self.drain_status();
    }

    /// Drain queued status-pipe messages onto the status endpoint.
    ///
    /// Sends from the FIFO head until the queue is empty or the endpoint
    /// reports `WouldBlock` (the entry is kept and retried on the next
    /// drain).
    ///
    /// Callers MUST invoke this after every batch of [`Self::enqueue_status`]
    /// calls made outside `pump` (e.g. at the end of an ISR service pass).
    /// The host only NAK-polls the status pipe while waiting for a
    /// ready/status IU, and NAKed polls raise no interrupt — a message left
    /// in the queue "until the next pump" therefore deadlocks the link
    /// (observed on hardware 2026-06-11: INQUIRY accepted and staged, RRDY
    /// enqueued but never written, no further interrupt arrived, host reset
    /// the device after 20 s).
    pub fn drain_status(&mut self) {
        while let Some(msg) = self.status_q.peek().copied() {
            if self.try_send_msg(msg) {
                self.status_q.pop();
            } else {
                break;
            }
        }
    }

    /// Read one packet from the command pipe and dispatch it.
    fn pump_cmd_pipe(&mut self) {
        let mut buf = [0u8; 32];
        match self.cmd_ep.read(&mut buf) {
            Ok(n) => {
                let raw = buf.get(..n).unwrap_or(&buf[..0]);
                self.dispatch_cmd(raw);
            }
            Err(UsbError::WouldBlock) => { /* nothing ready yet */ }
            Err(_e) => {
                trace!("uas: cmd pipe read error");
            }
        }
    }

    /// Dispatch a raw command-pipe packet.
    fn dispatch_cmd(&mut self, raw: &[u8]) {
        use crate::transport::uas::{IuParse, parse_iu};
        match parse_iu(raw) {
            Ok(IuParse::Command(iu)) => {
                if iu.lun != 0 {
                    trace!("uas: incorrect LUN {}", iu.lun);
                    let _ = self.status_q.push(StatusMsg::Response {
                        tag: iu.tag,
                        code: RC_INCORRECT_LUN,
                    });
                    return;
                }
                let kind = iu.parse_kind();
                match self.table.insert(iu.tag, iu.lun, kind) {
                    Ok(()) => {
                        trace!("uas: inserted tag {}", iu.tag);
                    }
                    Err(crate::transport::uas::InsertError::Overlapped) => {
                        trace!("uas: overlapped tag {}", iu.tag);
                        let _ = self.status_q.push(StatusMsg::Response {
                            tag: iu.tag,
                            code: RC_OVERLAPPED_TAG,
                        });
                    }
                    Err(crate::transport::uas::InsertError::Full) => {
                        trace!("uas: tag table full, tag {}", iu.tag);
                        let _ = self.status_q.push(StatusMsg::TaskSetFull { tag: iu.tag });
                    }
                }
            }
            Ok(IuParse::TaskMgmt(tm)) => {
                trace!("uas: task mgmt IU, function {}", tm.function);
                let _ = self.status_q.push(StatusMsg::Response {
                    tag: tm.tag,
                    code: RC_TMF_NOT_SUPPORTED,
                });
            }
            Err(_e) => {
                trace!("uas: cmd pipe parse error");
            }
        }
    }

    /// Encode `msg` and write it on the status pipe via the **packet
    /// (staging) path** — `Endpoint::write`, NOT the zero-copy
    /// `TransferBus::submit_write`.
    ///
    /// The packet path copies the IU into the driver's staging buffer, so
    /// the stack-local IU bytes need not outlive this call, and the driver
    /// auto-reaps retired fire-and-forget staging records on the next write.
    /// The zero-copy path is wrong here on both counts: its records must be
    /// retired via `poll_transfer` (which no one calls for the status pipe —
    /// HW-observed 2026-06-11: `tds_in_use` climbed 6→7→8 then permanent
    /// `WouldBlock`, muting the status pipe after ~8 IUs), and it DMAs the
    /// caller's buffer after the stack frame is gone.
    ///
    /// Returns `true` if the write was accepted; `false` on `WouldBlock`
    /// (caller keeps the message and retries next drain).
    fn try_send_msg(&self, msg: StatusMsg) -> bool {
        /// SAM SCSI status: GOOD.
        const SAM_STAT_GOOD: u8 = 0x00;
        /// SAM SCSI status: CHECK CONDITION.
        const SAM_STAT_CHECK_CONDITION: u8 = 0x02;
        /// SAM SCSI status: TASK SET FULL.
        const SAM_STAT_TASK_SET_FULL: u8 = 0x28;

        match msg {
            StatusMsg::ReadReady { tag } => {
                let iu = build_ready_iu(true, tag);
                self.status_ep.write(&iu).is_ok()
            }
            StatusMsg::WriteReady { tag } => {
                let iu = build_ready_iu(false, tag);
                self.status_ep.write(&iu).is_ok()
            }
            StatusMsg::Good { tag } => {
                let (iu, used) = build_status_iu(tag, SAM_STAT_GOOD, &[]);
                let bytes = iu.get(..used).unwrap_or(&iu[..STATUS_IU_HDR_LEN]);
                self.status_ep.write(bytes).is_ok()
            }
            StatusMsg::Check {
                tag,
                key,
                asc,
                ascq,
            } => {
                let sense = fixed_sense(key, asc, ascq);
                let (iu, used) = build_status_iu(tag, SAM_STAT_CHECK_CONDITION, &sense);
                let bytes = iu.get(..used).unwrap_or(&iu[..STATUS_IU_HDR_LEN]);
                self.status_ep.write(bytes).is_ok()
            }
            StatusMsg::TaskSetFull { tag } => {
                let (iu, used) = build_status_iu(tag, SAM_STAT_TASK_SET_FULL, &[]);
                let bytes = iu.get(..used).unwrap_or(&iu[..STATUS_IU_HDR_LEN]);
                self.status_ep.write(bytes).is_ok()
            }
            StatusMsg::Response { tag, code } => {
                let iu = build_response_iu(tag, code);
                self.status_ep.write(&iu).is_ok()
            }
        }
    }

    /// Enqueue a [`StatusMsg`] for later transmission on the status pipe.
    ///
    /// # Errors
    ///
    /// Returns [`StatusQueueFull`] only on a logic bug; the queue capacity
    /// covers every possible in-flight tag plus a margin.
    pub fn enqueue_status(&mut self, msg: StatusMsg) -> Result<(), StatusQueueFull> {
        self.status_q.push(msg)
    }

    /// Return `true` if no status messages are pending.
    pub fn status_drained(&self) -> bool {
        self.status_q.is_empty()
    }

    /// Submit a data-IN transfer (device → host) on the shared bulk-IN endpoint.
    ///
    /// Returns `WouldBlock` when the driver queue is full.
    pub fn submit_data_in<B: TransferBus>(&self, bus: &B, buf: &[u8]) -> Result<(), UsbError> {
        bus.submit_write(self.data_in, buf)
    }

    /// Poll for completion of the oldest pending data-IN transfer.
    ///
    /// Returns `Some(Ok(n))` on completion, `Some(Err(_))` on error, `None`
    /// while still in flight.
    pub fn poll_data_in<B: TransferBus>(&self, bus: &B) -> Option<Result<usize, UsbError>> {
        bus.poll_transfer(self.data_in)
    }

    /// Prime a data-OUT transfer (host → device) on the shared bulk-OUT endpoint.
    ///
    /// Returns `WouldBlock` when the driver queue is full.
    pub fn submit_data_out<B: TransferBus>(&self, bus: &B, buf: &mut [u8]) -> Result<(), UsbError> {
        bus.submit_read(self.data_out, buf)
    }

    /// Poll for completion of the oldest pending data-OUT transfer.
    ///
    /// Returns `Some(Ok(n))` on completion, `Some(Err(_))` on error, `None`
    /// while still in flight.
    pub fn poll_data_out<B: TransferBus>(&self, bus: &B) -> Option<Result<usize, UsbError>> {
        bus.poll_transfer(self.data_out)
    }

    /// Reset the engine: clear the tag table, flush the status queue.
    ///
    /// Called on USB reset or SET_INTERFACE to a new alternate setting.
    pub fn reset(&mut self) {
        self.table.clear();
        self.status_q.clear();
    }

    /// Write the alt-1 UAS endpoint descriptors to `writer` in f_tcm HS order.
    ///
    /// The data endpoints (`data_in_ep`, `data_out_ep`) are the shared BOT
    /// endpoints passed in from the caller; the status and command endpoints
    /// are owned by `self`.
    ///
    /// Order (§6.3 of the protocol reference):
    /// data-in + PU3, data-out + PU4, status + PU2, cmd + PU1.
    ///
    /// Each endpoint descriptor is immediately followed by its 4-byte Pipe
    /// Usage descriptor (`[0x04, 0x24, bPipeID, 0x00]`).
    pub(crate) fn write_alt1_descriptors(
        &self,
        writer: &mut usb_device::descriptor::DescriptorWriter,
        data_in_ep: &Endpoint<'alloc, Bus, In>,
        data_out_ep: &Endpoint<'alloc, Bus, Out>,
    ) -> usb_device::Result<()> {
        // data-in (shared BOT bulk IN): Pipe ID 3
        writer.endpoint(data_in_ep)?;
        writer.write(0x24, &[0x03, 0x00])?;

        // data-out (shared BOT bulk OUT): Pipe ID 4
        writer.endpoint(data_out_ep)?;
        writer.write(0x24, &[0x04, 0x00])?;

        // status (UAS-exclusive bulk IN): Pipe ID 2
        writer.endpoint(&self.status_ep)?;
        writer.write(0x24, &[0x02, 0x00])?;

        // command (UAS-exclusive bulk OUT): Pipe ID 1
        writer.endpoint(&self.cmd_ep)?;
        writer.write(0x24, &[0x01, 0x00])?;

        Ok(())
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
    fn test_parse_command_iu_lun1_reads_byte_9() -> TestResult {
        // Given: a Command IU addressing LUN 1 the way Linux int_to_scsilun()
        // encodes it — SAM peripheral addressing, byte 8 = 0x00 (method/bus),
        // byte 9 = 0x01 (the LUN). HW-observed encoding 2026-06-11.
        let mut raw = [0u8; 32];
        raw[0] = IU_ID_COMMAND;
        raw[3] = 0x01; // tag = 1
        raw[8] = 0x00; // address method / bus
        raw[9] = 0x01; // LUN 1
        raw[16] = 0x12; // INQUIRY

        // When
        let parsed = parse_iu(&raw).map_err(|_| "parse failed")?;

        // Then: lun must come from byte 9, not byte 8
        match parsed {
            IuParse::Command(iu) => {
                assert_eq!(iu.lun, 1, "LUN 1 must be read from IU byte 9");
            }
            IuParse::TaskMgmt(_) => panic!("expected Command, got TaskMgmt"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_command_iu_exotic_lun_encoding_rejected() -> TestResult {
        // Given: a LUN field that is not a clean single-level encoding
        // (non-zero address-method byte 8)
        let mut raw = [0u8; 32];
        raw[0] = IU_ID_COMMAND;
        raw[3] = 0x02; // tag = 2
        raw[8] = 0x40; // non-peripheral addressing method
        raw[16] = 0x12;

        // When
        let parsed = parse_iu(&raw).map_err(|_| "parse failed")?;

        // Then: collapses to the non-zero sentinel so callers reject it
        match parsed {
            IuParse::Command(iu) => {
                assert_eq!(
                    iu.lun,
                    u8::MAX,
                    "exotic LUN encodings must collapse to u8::MAX"
                );
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

    // -----------------------------------------------------------------------
    // StatusQueue tests (feature = "transfer" / "uas")
    // -----------------------------------------------------------------------

    /// Push N messages into the queue and verify they drain in FIFO order.
    #[cfg(feature = "transfer")]
    #[test]
    fn test_status_queue_fifo_order_and_capacity() -> TestResult {
        use super::{StatusMsg, StatusQueue};

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
    #[cfg(feature = "transfer")]
    #[test]
    fn test_status_queue_push_at_capacity_returns_full() -> TestResult {
        use super::{STATUS_QUEUE_CAP, StatusMsg, StatusQueue, StatusQueueFull};

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
}
