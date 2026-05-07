//! AstraGrid core mission kernel.
//!
//! The crate intentionally starts with one production-grade primitive:
//! an append-only, hash-chained mission ledger with admission policy checks.
//! Higher-level services can be replaced later without weakening the audit log.

pub mod event;
pub mod identity;
pub mod ledger;
pub mod policy;

pub use event::{Action, Actor, MissionEvent, Priority, Role};
pub use identity::{
    CommandAttestation, DetachedSignature, IdentityError, OperatorIdentity,
    OperatorKeyFileSecurity, OperatorKeypair, OperatorRegistry, OperatorRegistryEntry,
    OperatorStatus, RegistryError, RegistryImportStatus, SignedCommand,
};
pub use ledger::{
    AppendVerifiedReport, LedgerError, LedgerFailure, LedgerVerification, MissionLedger,
    PAYLOAD_LIMIT_BYTES,
};
pub use policy::{AdmissionPolicy, CommandRequest, PolicyDecision};
