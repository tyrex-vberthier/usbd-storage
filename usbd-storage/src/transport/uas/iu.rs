//! UAS Information Units: parsing what the host sends, building what the device answers.

use crate::subclass::scsi::{ScsiCommand, parse_cb};

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
pub(super) const STATUS_IU_HDR_LEN: usize = 16;

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
pub const FIXED_SENSE_LEN: usize = 18;

// ---------------------------------------------------------------------------
// IU structures
// ---------------------------------------------------------------------------

/// A parsed UAS Command IU.
///
/// Field `lun` is the single-level LUN collapsed from the 8-byte SAM LUN
/// field at IU offset 8 (see the field doc).  A non-zero LUN is **not** a
/// parse error: the caller must check `lun` and, if it is unsupported, send
/// a Response IU with [`RC_INCORRECT_LUN`](super::RC_INCORRECT_LUN).
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
/// Response IU carrying [`RC_INCORRECT_LUN`](super::RC_INCORRECT_LUN).
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

    if let (Some(dst), Some(src)) = (
        buf.get_mut(STATUS_IU_HDR_LEN..STATUS_IU_HDR_LEN + sense_copy_len),
        sense.get(..sense_copy_len),
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_task_mgmt_iu_length_boundary() -> TestResult {
        // Given: Task Management IUs of exactly 16 bytes and one byte short
        let mut raw = [0u8; 16];
        raw[0] = IU_ID_TASK_MGMT;
        raw[3] = 0x07; // tag 7

        // When / Then: 16 bytes parse, 15 bytes are too short
        assert!(
            matches!(
                parse_iu(&raw),
                Ok(IuParse::TaskMgmt(TaskMgmtIu { tag: 7, .. }))
            ),
            "a 16-byte Task Management IU should parse"
        );
        assert!(
            matches!(
                parse_iu(&raw[..15]),
                Err(IuParseError::TooShort {
                    expected: 16,
                    actual: 15
                })
            ),
            "a 15-byte Task Management IU should be too short"
        );
        Ok(())
    }

    #[test]
    fn test_parse_error_display() -> TestResult {
        let short = IuParseError::TooShort {
            expected: 32,
            actual: 3,
        };
        assert_eq!(short.to_string(), "IU too short: expected 32 bytes, got 3");
        let unknown = IuParseError::UnknownIuId { id: 0x2a };
        assert_eq!(unknown.to_string(), "unknown IU ID: 0x2a");
        Ok(())
    }

    #[test]
    fn test_response_iu_layout() -> TestResult {
        assert_eq!(
            build_response_iu(0x1234, super::super::RC_OVERLAPPED_TAG),
            [IU_ID_RESPONSE, 0, 0x12, 0x34, 0, 0, 0, 0x0a],
            "Response IU: ID, reserved, be16 tag, 3 zero bytes, response code"
        );
        Ok(())
    }

    #[test]
    fn test_fixed_sense_layout_masks_the_sense_key() -> TestResult {
        let sense = fixed_sense(0xF5, 0x24, 0x01);
        let mut expected = [0u8; FIXED_SENSE_LEN];
        expected[0] = 0x70;
        expected[2] = 0x05; // only the low 4 bits of the key
        expected[7] = 10;
        expected[12] = 0x24;
        expected[13] = 0x01;
        assert_eq!(sense, expected, "fixed-format sense layout");
        Ok(())
    }

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
