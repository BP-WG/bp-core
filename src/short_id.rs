// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
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

use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;

use bitcoin::{BlockHash, Txid};

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display(doc_comments)]
/// Errors from descriptor validation and parsing
pub enum Error {
    /// invalid block height
    BlockHeightOutOfRange,
    /// invalid tx input index
    InputIndexOutOfRange,
    /// invalid tx output index
    OutputIndexOutOfRange,
    /// invalid tx checksum
    ChecksumOutOfRange,
    /// tx dimension not defined
    DimensionRequired,
    /// descriptor upgrade
    UpgradeImpossible,
    /// descriptor downgrade
    DowngradeImpossible,
}

/// Checksum for block id data used by the LNPBP-5
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug,
    Display, From
)]
#[display("{0}", alt = "block_checksum:{0:#}")]
#[wrapper(FromStr, LowerHex, UpperHex, Octal)]
pub struct BlockChecksum(u8);

impl From<BlockHash> for BlockChecksum {
    fn from(block_hash: BlockHash) -> Self {
        let mut xor: u8 = 0;
        for byte in &block_hash[..] {
            xor ^= byte;
        }
        Self::from(xor)
    }
}

/// Checksum for transaction id data used by the LNPBP-5
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug,
    Display, From
)]
#[display("{0}", alt = "tx_checksum:{0:#}")]
#[wrapper(FromStr, LowerHex, UpperHex, Octal)]
pub struct TxChecksum(u64);

impl From<Txid> for TxChecksum {
    fn from(txid: Txid) -> Self {
        let mut checksum: u64 = 0;
        for (shift, byte) in txid.to_vec()[0..5].iter().enumerate() {
            checksum ^= (*byte as u64) << (shift * 8);
        }
        Self::from(checksum)
    }
}

/// Descriptor enum defines the onchain/offchain entity type
#[derive(Copy, Clone, Debug)]
pub enum Descriptor {
    /// Block included onchain
    OnchainBlock {
        /// Height of onchain block
        block_height: u32,
        /// Checksum of onchain block
        block_checksum: BlockChecksum,
    },
    /// Tx included onchain
    OnchainTransaction {
        /// Height of the block tx belongs to
        block_height: u32,
        /// Checksum of the block tx belongs to
        block_checksum: BlockChecksum,
        /// Index in the block tx belongs to
        tx_index: u16,
    },
    /// Tx input included onchain
    OnchainTxInput {
        /// Height of the block the tx input belongs to
        block_height: u32,
        /// Checksum of the block the tx input belongs to
        block_checksum: BlockChecksum,
        /// Index in the block tx belongs to
        tx_index: u16,
        /// Index in the tx the input belongs to
        input_index: u16,
    },
    /// Tx output included onchain
    OnchainTxOutput {
        /// Height of the block the tx input belongs to
        block_height: u32,
        /// Checksum of the block the tx input belongs to
        block_checksum: BlockChecksum,
        /// Index in the block tx belongs to
        tx_index: u16,
        /// Index in the tx the output belongs to
        output_index: u16,
    },
    /// Tx not included onchain
    OffchainTransaction {
        /// Offchain tx checksum
        tx_checksum: TxChecksum,
    },
    /// Tx input not included onchain
    OffchainTxInput {
        /// Offchain tx checksum
        tx_checksum: TxChecksum,
        /// Index in the tx the input belongs to
        input_index: u16,
    },
    /// Tx output not included onchain
    OffchainTxOutput {
        /// Offchain tx checksum
        tx_checksum: TxChecksum,
        /// Index in the tx the output belongs to
        output_index: u16,
    },
}

/// Dimension enum defines tx dimension scope in terms of input/output relation
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
pub enum Dimension {
    /// Tx input
    #[display("input")]
    Input,
    /// Tx output
    #[display("output")]
    Output,
}

impl Default for Descriptor {
    fn default() -> Self {
        Descriptor::OnchainBlock {
            block_height: 0,
            block_checksum: BlockChecksum::default(),
        }
    }
}

impl Descriptor {
    /// Verifies if Descriptor type has valid properties otherwise returns
    /// validation error
    pub fn try_validity(&self) -> Result<(), Error> {
        match *self {
            Descriptor::OnchainTransaction { block_height, .. }
            | Descriptor::OnchainTxInput { block_height, .. }
            | Descriptor::OnchainTxOutput { block_height, .. }
                if block_height >= (2u32 << 22) =>
            {
                Err(Error::BlockHeightOutOfRange)
            }
            Descriptor::OnchainTxInput { input_index, .. }
            | Descriptor::OffchainTxInput { input_index, .. }
                if input_index + 1 >= (2u16 << 14) =>
            {
                Err(Error::InputIndexOutOfRange)
            }
            Descriptor::OnchainTxOutput { output_index, .. }
            | Descriptor::OffchainTxOutput { output_index, .. }
                if output_index + 1 >= (2u16 << 14) =>
            {
                Err(Error::OutputIndexOutOfRange)
            }
            Descriptor::OffchainTransaction { tx_checksum, .. }
            | Descriptor::OffchainTxInput { tx_checksum, .. }
            | Descriptor::OffchainTxOutput { tx_checksum, .. }
                if *tx_checksum >= (2u64 << 46) =>
            {
                Err(Error::ChecksumOutOfRange)
            }
            _ => Ok(()),
        }
    }

    /// Returns true if Descriptor type is either OnchainBlock or
    /// OnchainTransaction or OnchainTxInput or OnchainTxOutput
    pub fn is_onchain(&self) -> bool {
        matches!(
            self,
            Descriptor::OnchainBlock { .. }
                | Descriptor::OnchainTransaction { .. }
                | Descriptor::OnchainTxInput { .. }
                | Descriptor::OnchainTxOutput { .. }
        )
    }

    /// Returns true if Descriptor type is not onchain type
    pub fn is_offchain(&self) -> bool { !self.is_onchain() }

    /// Upgraded returns the "wrapped descriptor" based on provided parameters.
    /// for instance, tx is returned in case descriptor is a block, as well as
    /// input/out is returned in case descriptor is a tx and dimension is
    /// specified
    pub fn upgraded(
        &self,
        index: u16,
        dimension: Option<Dimension>,
    ) -> Result<Self, Error> {
        use Dimension::*;

        match (*self, dimension) {
            (
                Descriptor::OnchainBlock {
                    block_height,
                    block_checksum,
                },
                None,
            ) => Ok(Descriptor::OnchainTransaction {
                block_height,
                block_checksum,
                tx_index: index,
            }),
            (
                Descriptor::OnchainTransaction {
                    block_height,
                    block_checksum,
                    tx_index,
                },
                Some(dim),
            ) if dim == Input => Ok(Descriptor::OnchainTxInput {
                block_height,
                block_checksum,
                tx_index,
                input_index: index,
            }),
            (
                Descriptor::OnchainTransaction {
                    block_height,
                    block_checksum,
                    tx_index,
                },
                Some(dim),
            ) if dim == Output => Ok(Descriptor::OnchainTxOutput {
                block_height,
                block_checksum,
                tx_index,
                output_index: index,
            }),
            (Descriptor::OffchainTransaction { tx_checksum }, Some(dim))
                if dim == Input =>
            {
                Ok(Descriptor::OffchainTxInput {
                    tx_checksum,
                    input_index: index,
                })
            }
            (Descriptor::OffchainTransaction { tx_checksum }, Some(dim))
                if dim == Output =>
            {
                Ok(Descriptor::OffchainTxOutput {
                    tx_checksum,
                    output_index: index,
                })
            }
            (Descriptor::OnchainTransaction { .. }, None)
            | (Descriptor::OffchainTransaction { .. }, None) => {
                Err(Error::DimensionRequired)
            }
            _ => Err(Error::UpgradeImpossible),
        }
    }

    /// Downgraded returns the "wrapper descriptor", i.e. in case the descriptor
    /// is an onchain tx, the onchain block is returned, as well as the onchain
    /// tx is returned for onchain input/output
    pub fn downgraded(self) -> Result<Self, Error> {
        match self {
            Descriptor::OnchainTransaction {
                block_height,
                block_checksum,
                ..
            } => Ok(Descriptor::OnchainBlock {
                block_height,
                block_checksum,
            }),
            Descriptor::OnchainTxInput {
                block_height,
                block_checksum,
                tx_index,
                ..
            }
            | Descriptor::OnchainTxOutput {
                block_height,
                block_checksum,
                tx_index,
                ..
            } => Ok(Descriptor::OnchainTransaction {
                block_height,
                block_checksum,
                tx_index,
            }),
            Descriptor::OffchainTxInput { tx_checksum, .. }
            | Descriptor::OffchainTxOutput { tx_checksum, .. } => {
                Ok(Descriptor::OffchainTransaction { tx_checksum })
            }
            _ => Err(Error::DowngradeImpossible),
        }
    }

    /// Get block height extracting from Descriptor
    pub fn get_block_height(&self) -> Option<u32> {
        match self {
            Descriptor::OnchainBlock { block_height, .. }
            | Descriptor::OnchainTransaction { block_height, .. }
            | Descriptor::OnchainTxInput { block_height, .. }
            | Descriptor::OnchainTxOutput { block_height, .. } => {
                Some(*block_height)
            }
            _ => None,
        }
    }

    /// Get block checksum extracting from Descriptor
    pub fn get_block_checksum(&self) -> Option<u8> {
        match self {
            Descriptor::OnchainBlock { block_checksum, .. }
            | Descriptor::OnchainTransaction { block_checksum, .. }
            | Descriptor::OnchainTxInput { block_checksum, .. }
            | Descriptor::OnchainTxOutput { block_checksum, .. } => {
                Some(**block_checksum)
            }
            _ => None,
        }
    }

    /// Get tx checksum extracting from Descriptor
    pub fn get_tx_checksum(&self) -> Option<u64> {
        match self {
            Descriptor::OffchainTransaction { tx_checksum, .. }
            | Descriptor::OffchainTxInput { tx_checksum, .. }
            | Descriptor::OffchainTxOutput { tx_checksum, .. } => {
                Some(**tx_checksum)
            }
            _ => None,
        }
    }

    /// Get tx index extracting from Descriptor
    pub fn get_tx_index(&self) -> Option<u16> {
        match self {
            Descriptor::OnchainTransaction { tx_index, .. }
            | Descriptor::OnchainTxInput { tx_index, .. }
            | Descriptor::OnchainTxOutput { tx_index, .. } => Some(*tx_index),
            _ => None,
        }
    }

    /// Get input index extracting from Descriptor
    pub fn get_input_index(&self) -> Option<u16> {
        match self {
            Descriptor::OnchainTxInput { input_index, .. }
            | Descriptor::OffchainTxInput { input_index, .. } => {
                Some(*input_index)
            }
            _ => None,
        }
    }

    /// Get output index extracting from Descriptor
    pub fn get_output_index(&self) -> Option<u16> {
        match self {
            Descriptor::OnchainTxOutput { output_index, .. }
            | Descriptor::OffchainTxOutput { output_index, .. } => {
                Some(*output_index)
            }
            _ => None,
        }
    }

    /// Tries to convert short id from Descriptor to u64
    pub fn try_into_u64(self) -> Result<u64, Error> {
        ShortId::try_from(self).map(ShortId::into_u64)
    }
}

/// Short id is a descriptor representation that allows to build a Descriptor
/// starting from a specific mask
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode
)]
#[display("{0:016X}")]
pub struct ShortId(u64);

impl ShortId {
    /// Specifies offchain descriptor
    pub const FLAG_OFFCHAIN: u64 = 0x8000_0000_0000_0000;
    /// Specifies block descriptor and allows block height definition
    pub const MASK_BLOCK: u64 = 0x7FFF_FF00_0000_0000;
    /// Allows block checksum definition
    pub const MASK_BLOCKCHECK: u64 = 0x0000_00FF_0000_0000;
    /// Allows tx index definition
    pub const MASK_TXIDX: u64 = 0x0000_0000_FFFF_0000;
    /// Allows tx checksum definition
    pub const MASK_TXCHECK: u64 = 0x7FFF_FFFF_FFFF_0000;
    /// Specifies tx input or output descriptor
    pub const FLAG_INOUT: u64 = 0x0000_0000_0000_8000;
    /// Allows tx index definition and specifies tx descriptor
    pub const MASK_INOUT: u64 = 0x0000_0000_0000_7FFF;

    /// Operation for block height definition
    pub const SHIFT_BLOCK: u64 = 40;
    /// Operation for block checksum definition
    pub const SHIFT_BLOCKCHECK: u64 = 32;
    /// Operation for tx id and tx checksum definition
    pub const SHIFT_TXIDX: u64 = 16;

    /// Returns if onchain descriptor is represented
    pub fn is_onchain(&self) -> bool {
        self.0 & Self::FLAG_OFFCHAIN != Self::FLAG_OFFCHAIN
    }
    /// Returns if offchain descriptor is represented
    pub fn is_offchain(&self) -> bool {
        self.0 & Self::FLAG_OFFCHAIN == Self::FLAG_OFFCHAIN
    }

    /// Generates descriptor from short id definition
    pub fn get_descriptor(&self) -> Descriptor {
        #[inline]
        fn iconv<T>(val: u64) -> T
        where
            T: TryFrom<u64>,
            <T as TryFrom<u64>>::Error: Debug,
        {
            val.try_into()
                .expect("Conversion from existing ShortId can't fail")
        }

        let index: u16 = iconv(self.0 & Self::MASK_INOUT);

        if self.is_onchain() {
            let block_height: u32 =
                iconv((self.0 & Self::MASK_BLOCK) >> Self::SHIFT_BLOCK);
            let block_checksum = BlockChecksum::from(iconv::<u8>(
                (self.0 & Self::MASK_BLOCKCHECK) >> Self::SHIFT_BLOCKCHECK,
            ));
            if (self.0 & (!Self::MASK_BLOCK)) == 0 {
                return Descriptor::OnchainBlock {
                    block_height,
                    block_checksum,
                };
            }
            let tx_index: u16 =
                iconv((self.0 & Self::MASK_TXIDX) >> Self::SHIFT_TXIDX);
            if (self.0 & (!Self::MASK_INOUT)) == 0 {
                return Descriptor::OnchainTransaction {
                    block_height,
                    block_checksum,
                    tx_index,
                };
            }
            if (self.0 & Self::FLAG_INOUT) == 0 {
                Descriptor::OnchainTxInput {
                    block_height,
                    block_checksum,
                    tx_index,
                    input_index: index - 1,
                }
            } else {
                Descriptor::OnchainTxOutput {
                    block_height,
                    block_checksum,
                    tx_index,
                    output_index: index - 1,
                }
            }
        } else {
            let tx_checksum = TxChecksum::from(
                (self.0 & Self::MASK_TXCHECK) >> Self::SHIFT_TXIDX,
            );
            if (self.0 & (!Self::MASK_INOUT)) == 0 {
                return Descriptor::OffchainTransaction { tx_checksum };
            }
            if (self.0 & Self::FLAG_INOUT) == 0 {
                Descriptor::OffchainTxInput {
                    tx_checksum,
                    input_index: index - 1,
                }
            } else {
                Descriptor::OffchainTxOutput {
                    tx_checksum,
                    output_index: index - 1,
                }
            }
        }
    }

    /// Converts short id into inner u64
    pub fn into_u64(self) -> u64 { self.into() }
}

impl From<ShortId> for Descriptor {
    fn from(short_id: ShortId) -> Self { short_id.get_descriptor() }
}

impl TryFrom<Descriptor> for ShortId {
    type Error = self::Error;

    fn try_from(descriptor: Descriptor) -> Result<Self, Self::Error> {
        use Descriptor::*;

        descriptor.try_validity()?;

        let block_height: u64 = match descriptor {
            OnchainBlock { block_height, .. }
            | OnchainTransaction { block_height, .. }
            | OnchainTxInput { block_height, .. }
            | OnchainTxOutput { block_height, .. } => block_height,
            _ => 0,
        } as u64;
        let block_checksum = *match descriptor {
            OnchainBlock { block_checksum, .. }
            | OnchainTransaction { block_checksum, .. }
            | OnchainTxInput { block_checksum, .. }
            | OnchainTxOutput { block_checksum, .. } => block_checksum,
            _ => BlockChecksum::default(),
        } as u64;
        let tx_index = match descriptor {
            OnchainTransaction { tx_index, .. }
            | OnchainTxInput { tx_index, .. }
            | OnchainTxOutput { tx_index, .. } => tx_index,
            _ => 0,
        } as u64;
        let tx_checksum = match descriptor {
            OffchainTransaction { tx_checksum }
            | OffchainTxInput { tx_checksum, .. }
            | OffchainTxOutput { tx_checksum, .. } => tx_checksum,
            _ => TxChecksum::default(),
        };
        let inout_index: u64 = match descriptor {
            OnchainTxInput { input_index, .. }
            | OffchainTxInput { input_index, .. } => input_index + 1,
            OnchainTxOutput { output_index, .. }
            | OffchainTxOutput { output_index, .. } => output_index + 1,
            _ => 0,
        } as u64;

        let mut short_id = 0u64;
        short_id |= inout_index;
        if descriptor.is_offchain() {
            short_id |= Self::FLAG_OFFCHAIN;
            short_id |=
                (*tx_checksum << Self::SHIFT_TXIDX) & Self::MASK_TXCHECK;
        } else {
            short_id |= (block_height << 40) & Self::MASK_BLOCK;
            short_id |= (block_checksum << Self::SHIFT_BLOCKCHECK)
                & Self::MASK_BLOCKCHECK;
            short_id |= (tx_index << 16) & Self::MASK_TXIDX;
        }

        match descriptor {
            OnchainTxOutput { .. } | OffchainTxOutput { .. } => {
                short_id |= Self::FLAG_INOUT << Self::SHIFT_TXIDX
            }
            _ => (),
        }

        Ok(Self(short_id))
    }
}

impl From<u64> for ShortId {
    fn from(val: u64) -> Self { Self(val) }
}

impl From<ShortId> for u64 {
    fn from(short_id: ShortId) -> Self { short_id.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_id_is_onchain() {
        let test_cases = vec![
            0,
            1,
            100,
            16,
            32,
            40,
            0x7FFF_FF00_0000_0000,
            0x0000_0000_0000_8000,
        ];
        for c in &test_cases {
            let sid = ShortId(*c);
            assert!(sid.is_onchain());
        }
    }

    #[test]
    fn short_id_is_offchain() {
        let test_cases = vec![
            0x8000_0000_0000_0000,
            0x8000_0000_0000_0001,
            0x9000_0000_0000_0000,
            0xFFFF_0000_0000_0000,
        ];
        for c in &test_cases {
            let sid = ShortId(*c);
            assert!(sid.is_offchain());
        }
    }

    #[test]
    fn short_id_into() {
        let test_cases = [0, 1];
        for c in &test_cases {
            let sid = ShortId(*c);
            assert_eq!(sid.into_u64(), *c);
        }
    }

    #[test]
    fn short_id_get_descriptor_empty() {
        let sid = ShortId(0);
        let descriptor = sid.get_descriptor();
        match descriptor.get_block_height() {
            Some(h) => assert_eq!(h, 0),
            None => {}
        }
    }

    #[test]
    fn short_id_get_descriptor_block_height_valid() {
        let test_cases = [
            [0x0000_0100_0000_0000, 1],
            [0x0000_1000_0000_0000, 16],
            [0x0001_0000_0000_0000, 256],
        ];
        for c in &test_cases {
            let sid = ShortId(c[0]);
            match sid.get_descriptor().get_block_height() {
                Some(h) => assert_eq!(u64::from(h), c[1]),
                None => {}
            }
        }
    }

    #[test]
    #[cfg(not(codecov))]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn short_id_get_descriptor_block_height_overflow() {
        let sid = ShortId(0x0000_0000_1000_0000);
        sid.get_descriptor().get_block_height();
    }
}
