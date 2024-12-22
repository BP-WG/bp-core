// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! Deterministic bitcoin commitments library.
//!
//! Deterministic bitcoin commitments are part of the client-side-validation.
//! They allow to embed commitment to extra-transaction data into a bitcoin
//! transaction in a provable way, such that it can always be proven that a
//! given transaction contains one and only one commitment of a specific type
//! for a given commitment protocol.

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
#[macro_use]
extern crate strict_encoding;
extern crate commit_verify;

/// Name of the strict type library generated from the data types in this crate.
pub const LIB_NAME_BPCORE: &str = "BPCore";

pub mod keytweak;
pub mod opret;
pub mod sigtweak;
pub mod tapret;
mod proof;

pub use proof::{Method, MethodParseError, Proof};
