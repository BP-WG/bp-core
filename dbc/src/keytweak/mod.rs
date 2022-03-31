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

//! Homomorphic key tweaking-based deterministic commitment scheme.
//!
//! **Embed-commit:**
//! a) `PublicKey, Msg -> PublicKey', PublicKey`;
//! b) `Set<PublicKey>, Msg -> Set<PublicKey>', PublicKey`;
//! c) `LockScript, Msg -> LockScript', (LockScript, PublicKey)`;
//! d) `(psbt::Output, TxOut), Msg -> (psbt::Output, TxOut)', KeytweakProof`;
//! e) `PSBT, Msg -> PSBT', KeytweakProof`;
//! **Convolve-commit:**
//! d) `PubkeyScript, SpkDescriptor, Msg -> PubkeyScript'`;
//! e) `TxOut, SpkDescriptor, Msg -> TxOut'`;
//! f) `Tx, SpkDescriptor, Msg -> Tx'`;
