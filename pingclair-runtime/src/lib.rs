// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧰 Runtime services every transport shares.
//!
//! The access log is not an HTTP feature: nginx's `stream` module writes the
//! same kind of record for a proxied TCP connection, and this project's L4
//! listener will have to do the same. Keeping the records, the destination
//! selection and the writers here — instead of inside the HTTP proxy — is what
//! lets a second transport log through one implementation rather than growing
//! a second answer to "where does this line go".
//!
//! 📌 Nothing here runs on the request path except the two lookups the callers
//! make: a precomputed [`access_log::LogTargets::select`] walk and the
//! redaction predicates. Formatting and writing happen on the destination's
//! own thread, behind a bounded queue.

pub mod access_log;
pub mod redaction;
