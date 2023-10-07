// Bitcoin protocol consensus library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

use std::iter::Sum;
use std::ops::{Add, AddAssign};

use crate::{LenVarInt, ScriptPubkey, SigScript, Tx, TxIn, TxOut, Witness, LIB_NAME_BITCOIN};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[display("{0} vbytes")]
pub struct VBytes(u32);

impl Add for VBytes {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output { Self(self.0 + rhs.0) }
}

impl AddAssign for VBytes {
    fn add_assign(&mut self, rhs: Self) { self.0.add_assign(rhs.0) }
}

impl Sum for VBytes {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self { Self(iter.map(Self::into_u32).sum()) }
}

impl VBytes {
    pub fn to_u32(&self) -> u32 { self.0 }
    pub fn into_u32(self) -> u32 { self.0 }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[display("{0} WU")]
pub struct WeightUnits(u32);

impl Add for WeightUnits {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output { Self(self.0 + rhs.0) }
}

impl AddAssign for WeightUnits {
    fn add_assign(&mut self, rhs: Self) { self.0.add_assign(rhs.0) }
}

impl Sum for WeightUnits {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self { Self(iter.map(Self::into_u32).sum()) }
}

impl From<WeightUnits> for VBytes {
    fn from(wu: WeightUnits) -> Self { Self((wu.0 as f32 / 4.0).ceil() as u32) }
}

impl WeightUnits {
    pub fn no_discount(bytes: usize) -> Self { WeightUnits(bytes as u32 * 4) }
    pub fn witness_discount(bytes: usize) -> Self { WeightUnits(bytes as u32) }
    pub fn to_u32(&self) -> u32 { self.0 }
    pub fn into_u32(self) -> u32 { self.0 }
}

pub trait Weight {
    fn weight_units(&self) -> WeightUnits;

    #[inline]
    fn vbytes(&self) -> VBytes { VBytes::from(self.weight_units()) }
}

impl Weight for Tx {
    fn weight_units(&self) -> WeightUnits {
        let bytes = 4 // version
        + self.inputs.len_var_int().len()
        + self.outputs.len_var_int().len()
        + 4; // lock time

        let mut weight = WeightUnits::no_discount(bytes) +
            self.inputs().map(TxIn::weight_units).sum() +
            self.outputs().map(TxOut::weight_units).sum();
        if self.is_segwit() {
            weight += WeightUnits::witness_discount(2); // marker and flag bytes
            weight += self
                .inputs()
                .map(|txin| &txin.witness)
                .map(Witness::weight_units)
                .sum();
        }
        weight
    }
}

impl Weight for TxIn {
    fn weight_units(&self) -> WeightUnits {
        WeightUnits::no_discount(
            32 // txid
            + 4 // vout
            + 4, // nseq
        ) + self.sig_script.weight_units()
    }
}

impl Weight for TxOut {
    fn weight_units(&self) -> WeightUnits {
        WeightUnits::no_discount(8) // value
        + self.script_pubkey.weight_units()
    }
}

impl Weight for ScriptPubkey {
    fn weight_units(&self) -> WeightUnits {
        WeightUnits::no_discount(self.len_var_int().len() + self.len())
    }
}

impl Weight for SigScript {
    fn weight_units(&self) -> WeightUnits {
        WeightUnits::no_discount(self.len_var_int().len() + self.len())
    }
}

impl Weight for Witness {
    fn weight_units(&self) -> WeightUnits {
        WeightUnits::witness_discount(
            self.len_var_int().len() +
                self.iter()
                    .map(|item| item.len_var_int().len() + item.len())
                    .sum::<usize>(),
        )
    }
}
