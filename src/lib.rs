// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

//! Primitives module defines core strict interfaces from informational LNPBP
//! standards specifying secure and robust practices for function calls
//! used in main LNP/BP development paradigms:
//! * Cryptographic commitments and verification
//! * Single-use seals
//! * Client-side validation
//! * Strict binary data serialization used by client-side validation
//!
//! The goal of this module is to maximally reduce the probability of errors and
//! mistakes within particular implementations of this paradigms by
//! standardizing typical workflow processes in a form of interfaces that
//! will be nearly impossible to use in the wrong form.

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

mod short_id;
