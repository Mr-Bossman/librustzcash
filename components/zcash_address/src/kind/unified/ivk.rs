use std::cmp;
use std::convert::{TryFrom, TryInto};

use crate::kind;

use super::{
    private::{self, Receiver as PrivateReceiver},
    ParseError, Typecode, Unified,
};

/// The set of known IVKs for Unified IVKs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ivk {
    /// The raw encoding of an Orchard Incoming Viewing Key.
    ///
    /// `(dk, ivk)` each 32 bytes.
    Orchard([u8; 64]),

    /// Data contained within the Sapling component of a Unified Incoming Viewing Key.
    ///
    /// In order to ensure that Unified Addresses can always be derived from UIVKs, we
    /// store more data here than was specified to be part of a Sapling IVK. Specifically,
    /// we store the same data here as we do for Orchard.
    ///
    /// `(dk, ivk)` each 32 bytes.
    Sapling([u8; 64]),

    /// The extended public key for the BIP 44 account corresponding to the transparent
    /// address subtree from which transparent addresses are derived.
    ///
    /// Transparent addresses don't have "viewing keys" - the addresses themselves serve
    /// that purpose. However, we want the ability to derive diversified Unified Addresses
    /// from Unified Viewing Keys, and to not break the unlinkability property when they
    /// include transparent receivers. To achieve this, we treat the last hardened node in
    /// the BIP 44 derivation path as the "transparent viewing key"; all addresses derived
    /// from this node use non-hardened derivation, and can thus be derived just from this
    /// extended public key.
    P2pkh([u8; 78]),

    /// The raw data of a P2SH address.
    ///
    /// # Security
    ///
    /// P2SH addresses are hashes of scripts, and as such have no generic HD mechanism for
    /// us to derive independent-but-linked P2SH addresses. As such, if someone constructs
    /// a UIVK containing a P2SH address, and then derives diversified UAs from it, those
    /// UAs will be trivially linkable as they will share the same P2SH address.
    P2sh(kind::p2sh::Data),

    Unknown {
        typecode: u8,
        data: Vec<u8>,
    },
}

impl cmp::Ord for Ivk {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.typecode().cmp(&other.typecode()) {
            cmp::Ordering::Equal => self.data().cmp(other.data()),
            res => res,
        }
    }
}

impl cmp::PartialOrd for Ivk {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<(u8, Vec<u8>)> for Ivk {
    type Error = ParseError;

    fn try_from((typecode, addr): (u8, Vec<u8>)) -> Result<Self, Self::Error> {
        match typecode.into() {
            Typecode::P2pkh => addr.try_into().map(Ivk::P2pkh),
            Typecode::P2sh => addr.try_into().map(Ivk::P2sh),
            Typecode::Sapling => addr.try_into().map(Ivk::Sapling),
            Typecode::Orchard => addr.try_into().map(Ivk::Orchard),
            Typecode::Unknown(_) => Ok(Ivk::Unknown {
                typecode,
                data: addr,
            }),
        }
        .map_err(|_| ParseError::InvalidEncoding)
    }
}

impl private::Receiver for Ivk {
    fn typecode(&self) -> Typecode {
        match self {
            Ivk::P2pkh(_) => Typecode::P2pkh,
            Ivk::P2sh(_) => Typecode::P2sh,
            Ivk::Sapling(_) => Typecode::Sapling,
            Ivk::Orchard(_) => Typecode::Orchard,
            Ivk::Unknown { typecode, .. } => Typecode::Unknown(*typecode),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            Ivk::P2pkh(data) => data,
            Ivk::P2sh(data) => data,
            Ivk::Sapling(data) => data,
            Ivk::Orchard(data) => data,
            Ivk::Unknown { data, .. } => data,
        }
    }
}

/// A Unified Incoming Viewing Key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Uivk(pub(crate) Vec<Ivk>);

impl Unified for Uivk {
    /// The HRP for a Bech32m-encoded mainnet Unified IVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET: &'static str = "uivk";

    /// The HRP for a Bech32m-encoded testnet Unified IVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET: &'static str = "uivktest";

    /// The HRP for a Bech32m-encoded regtest Unified IVK.
    const REGTEST: &'static str = "uivkregtest";

    /// Returns the IVKs contained within this UIVK, in the order they were
    /// parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Uivk::receivers`.
    fn receivers_as_parsed(&self) -> &[Ivk] {
        &self.0
    }
}

impl private::Sealed for Uivk {
    type Receiver = Ivk;

    fn from_inner(ivks: Vec<Self::Receiver>) -> Self {
        Self(ivks)
    }
}
