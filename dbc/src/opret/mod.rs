// Deterministic bitcoin commitments library, implementing LNPBP standards
// Part of bitcoin protocol core library (BP Core Lib)
//
// Written in 2020-2022 by
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

//! ScriptPubkey-based OP_RETURN commitments.
//!
//! **Commit:**
//! a) `Msg -> ScriptPubkey`;
//! b) `Msg -> TxOut`;
//! c) `Msg -> (psbt::Output, TxOut)`;
//! **Convolve-commit:**
//! d) `Tx, Amount, Msg -> Tx'`;
//! e) `Psbt, Amount, Msg -> Psbt'`.
