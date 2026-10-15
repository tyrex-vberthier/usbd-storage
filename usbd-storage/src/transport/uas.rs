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
//! All IU field offsets and constants in this module come verbatim from the
//! Linux `include/linux/usb/uas.h` header (kernel commit
//! `9716c086c8e8b141d35aa61f2e96a2e83de212a7`).

mod iu;
mod tags;

pub use iu::{
    CommandIu, FIXED_SENSE_LEN, IuParse, IuParseError, TaskMgmtIu, build_ready_iu,
    build_response_iu, build_status_iu, fixed_sense, parse_iu,
};
pub use tags::{InsertError, TagSlot, TagTable};

// ---------------------------------------------------------------------------
// Protocol constants (all from uas.h §1 / §3)
// ---------------------------------------------------------------------------

/// Host-side queue depth the Linux `uas` driver uses at High Speed.
///
/// Tags are 1-based integers in `1..=UAS_QDEPTH`; up to `UAS_QDEPTH − 2 = 30`
/// may be in flight concurrently (the host reserves two slots internally).
pub const UAS_QDEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Response codes (uas.h §4)
// ---------------------------------------------------------------------------

/// Response code: task management function not supported.
pub const RC_TMF_NOT_SUPPORTED: u8 = 0x04;
/// Response code: incorrect LUN addressed.
pub const RC_INCORRECT_LUN: u8 = 0x09;
/// Response code: overlapped tag attempted.
pub const RC_OVERLAPPED_TAG: u8 = 0x0a;
