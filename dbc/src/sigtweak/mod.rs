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

//! Signature tweaking-based deterministic commitment scheme.
//!
//! **Sign-commit:**
//! a) `PrivateKey, Msg -> ecdsa::Signature`;
//! b) `KeyPair, Msg -> bip340::Signature`;
//! **Convolve-commit:**
//! c) `psbt::Input, PrivateKey, Msg -> psbt::Input'`;
//! d) `psbt::Input, KeyPair, Msg -> psbt::Input'`;
