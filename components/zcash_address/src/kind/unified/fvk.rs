use std::cmp;
use std::convert::{TryFrom, TryInto};

use crate::kind;

use super::{
    private::{self, Receiver as PrivateReceiver},
    ParseError, Typecode, Unified,
};

/// The set of known FVKs for Unified FVKs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Fvk {
    /// The raw encoding of an Orchard Full Viewing Key.
    ///
    /// `(ak, nk, rivk)` each 32 bytes.
    Orchard([u8; 96]),

    /// Data contained within the Sapling component of a Unified Full Viewing Key
    ///
    /// `(ak, nk, ovk)` each 32 bytes.
    Sapling([u8; 96]),

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
    /// a UFVK containing a P2SH address, and then derives diversified UAs from it, those
    /// UAs will be trivially linkable as they will share the same P2SH address.
    P2sh(kind::p2sh::Data),

    Unknown {
        typecode: u8,
        data: Vec<u8>,
    },
}

impl cmp::Ord for Fvk {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.typecode().cmp(&other.typecode()) {
            cmp::Ordering::Equal => self.data().cmp(other.data()),
            res => res,
        }
    }
}

impl cmp::PartialOrd for Fvk {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<(u8, Vec<u8>)> for Fvk {
    type Error = ParseError;

    fn try_from((typecode, addr): (u8, Vec<u8>)) -> Result<Self, Self::Error> {
        match typecode.into() {
            Typecode::P2pkh => addr.try_into().map(Fvk::P2pkh),
            Typecode::P2sh => addr.try_into().map(Fvk::P2sh),
            Typecode::Sapling => addr.try_into().map(Fvk::Sapling),
            Typecode::Orchard => addr.try_into().map(Fvk::Orchard),
            Typecode::Unknown(_) => Ok(Fvk::Unknown {
                typecode,
                data: addr,
            }),
        }
        .map_err(|_| ParseError::InvalidEncoding)
    }
}

impl private::Receiver for Fvk {
    fn typecode(&self) -> Typecode {
        match self {
            Fvk::P2pkh(_) => Typecode::P2pkh,
            Fvk::P2sh(_) => Typecode::P2sh,
            Fvk::Sapling(_) => Typecode::Sapling,
            Fvk::Orchard(_) => Typecode::Orchard,
            Fvk::Unknown { typecode, .. } => Typecode::Unknown(*typecode),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            Fvk::P2pkh(data) => data,
            Fvk::P2sh(data) => data,
            Fvk::Sapling(data) => data,
            Fvk::Orchard(data) => data,
            Fvk::Unknown { data, .. } => data,
        }
    }
}

/// A Unified Full Viewing Key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ufvk(pub(crate) Vec<Fvk>);

impl Unified for Ufvk {
    /// The HRP for a Bech32m-encoded mainnet Unified FVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET: &'static str = "uview";

    /// The HRP for a Bech32m-encoded testnet Unified FVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET: &'static str = "uviewtest";

    /// The HRP for a Bech32m-encoded regtest Unified FVK.
    const REGTEST: &'static str = "uviewregtest";

    /// Returns the FVKs contained within this UFVK, in the order they were
    /// parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Ufvk::receivers`.
    fn receivers_as_parsed(&self) -> &[Fvk] {
        &self.0
    }
}

impl private::Sealed for Ufvk {
    type Receiver = Fvk;

    fn from_inner(fvks: Vec<Self::Receiver>) -> Self {
        Self(fvks)
    }
}

#[cfg(test)]
mod tests {
    use proptest::{
        array::{uniform20, uniform32},
        prelude::*,
    };

    use super::{Fvk, ParseError, Typecode, Ufvk};
    use crate::kind::unified::Unified;

    prop_compose! {
        fn uniform96()(a in uniform32(0u8..), b in uniform32(0u8..), c in uniform32(0u8..)) -> [u8; 96] {
            let mut fvk = [0; 96];
            fvk[..32].copy_from_slice(&a);
            fvk[32..64].copy_from_slice(&b);
            fvk[64..].copy_from_slice(&c);
            fvk
        }
    }

    prop_compose! {
        fn uniform78()(a in uniform96()) -> [u8; 78] {
            let mut c = [0; 78];
            c[..78].copy_from_slice(&a[..78]);
            c
        }
    }

    fn arb_shielded_fvk() -> BoxedStrategy<Fvk> {
        prop_oneof![
            uniform96().prop_map(Fvk::Sapling),
            uniform96().prop_map(Fvk::Orchard),
        ]
        .boxed()
    }

    fn arb_transparent_fvk() -> BoxedStrategy<Fvk> {
        prop_oneof![
            uniform78().prop_map(Fvk::P2pkh),
            uniform20(0u8..).prop_map(Fvk::P2sh),
        ]
        .boxed()
    }

    prop_compose! {
        fn arb_unified_fvk()(
            shielded in prop::collection::hash_set(arb_shielded_fvk(), 1..2),
            transparent in prop::option::of(arb_transparent_fvk()),
        ) -> Ufvk {
            Ufvk(shielded.into_iter().chain(transparent).collect())
        }
    }

    proptest! {
        #[test]
        fn ufvk_roundtrip(
            hrp in prop_oneof![Ufvk::MAINNET, Ufvk::TESTNET, Ufvk::REGTEST],
            ufvk in arb_unified_fvk(),
        ) {
            let bytes = ufvk.to_bytes(&hrp);
            let decoded = Ufvk::from_bytes(hrp.as_str(), &bytes[..]);
            prop_assert_eq!(decoded, Ok(ufvk));
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Ufvk(vec![Fvk::Orchard([1; 96])])` as base.

        // Invalid padding ([0xff; 16] instead of [b'u', 0x00, 0x00, 0x00...])
        let invalid_padding = vec![
            0xc6, 0xf3, 0x68, 0xdd, 0x13, 0xcd, 0x8c, 0x4e, 0x7b, 0xa3, 0x27, 0xf0, 0xe8, 0x66,
            0x35, 0xbf, 0x85, 0x34, 0xf7, 0x48, 0x6c, 0x1, 0xa6, 0xf5, 0x63, 0x56, 0x23, 0x5a,
            0x57, 0xbb, 0x2f, 0x88, 0x8f, 0xf3, 0x41, 0xf5, 0xf2, 0x7, 0xe7, 0x4, 0x31, 0x97, 0xf0,
            0x4f, 0xac, 0xad, 0x84, 0x95, 0x2c, 0x1a, 0x4a, 0x21, 0x3e, 0xf6, 0x11, 0xcb, 0x8,
            0x29, 0xbb, 0x74, 0xf6, 0x4b, 0x35, 0xc4, 0xdd, 0x5b, 0x72, 0xac, 0x77, 0x19, 0x5f,
            0x76, 0x5d, 0xaf, 0x58, 0x4e, 0xaf, 0x84, 0x8a, 0xa8, 0xab, 0xeb, 0x99, 0x94, 0xe,
            0x61, 0xbe, 0x7, 0xef, 0x2a, 0xad, 0x63, 0x2e, 0xe1, 0xed, 0x36, 0x88, 0xec, 0x7a,
            0x44, 0xc0, 0x13, 0x3e, 0x74, 0x6c, 0x59, 0x8a, 0x75, 0x9b, 0x5f, 0xfe, 0xc5, 0x9f,
            0x1,
        ];
        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &invalid_padding[..]),
            Err(ParseError::InvalidEncoding)
        );

        // Short padding (padded to 15 bytes instead of 16)
        let truncated_padding = vec![
            0x94, 0x5d, 0x16, 0x66, 0x9a, 0x80, 0x7, 0x44, 0xbd, 0x21, 0xa4, 0x24, 0x4b, 0x50,
            0x77, 0xe7, 0xaf, 0xbb, 0xc7, 0xf7, 0x75, 0x8e, 0xb, 0xda, 0xb4, 0xed, 0x13, 0x66,
            0xe1, 0x65, 0xa5, 0xa3, 0x0, 0xf9, 0x3a, 0x93, 0x70, 0xa7, 0xd5, 0x17, 0x25, 0xb7,
            0x28, 0xa6, 0x24, 0xdf, 0xd2, 0xf, 0x53, 0x38, 0x86, 0xdf, 0xd2, 0x6, 0xd3, 0xac, 0xdf,
            0x5a, 0x9c, 0x5e, 0x73, 0x8c, 0xb4, 0xa3, 0x88, 0x49, 0xd7, 0x60, 0x20, 0xb1, 0x26,
            0x4, 0xcf, 0x73, 0xa0, 0x1f, 0x35, 0x18, 0x5a, 0xfa, 0xc7, 0x4, 0x91, 0x4, 0x54, 0x69,
            0x67, 0x3e, 0xef, 0x59, 0x28, 0xd6, 0x7, 0x25, 0xd4, 0xa7, 0xd6, 0x18, 0xce, 0x1f,
            0x7b, 0x58, 0x9d, 0x68, 0x4, 0x2, 0xb5, 0x44, 0xcd, 0x74, 0x96, 0xb4, 0x9b,
        ];
        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &truncated_padding[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn truncated() {
        // The test cases below start from an encoding of
        //     `Ufvk(vec![Fvk::Orchard([1; 96]), Fvk::Sapling([2; 96])])`
        // with the fvk data truncated, but valid padding.

        // - Missing the last data byte of the Sapling fvk.
        let truncated_sapling_data = vec![
            0xdb, 0xa5, 0x3c, 0x5f, 0x9b, 0xa9, 0x78, 0x43, 0x9b, 0x49, 0x46, 0x91, 0x3d, 0x8a,
            0xfe, 0x4b, 0x7f, 0xe4, 0x6, 0x5a, 0xac, 0xa, 0xa3, 0x99, 0xa2, 0x1a, 0xab, 0xed, 0xf6,
            0xb5, 0x9, 0xea, 0x3a, 0xc0, 0xb8, 0xee, 0xc8, 0x52, 0x35, 0xa8, 0x8d, 0xc2, 0xc8,
            0x1a, 0xac, 0x1c, 0x0, 0x3d, 0xd4, 0xcc, 0xd, 0x2a, 0x6, 0x1d, 0x6c, 0x51, 0xe7, 0xb3,
            0xea, 0x37, 0x18, 0x4b, 0x61, 0x64, 0x3, 0x18, 0x4d, 0x50, 0x47, 0xa7, 0x81, 0xec,
            0x79, 0x36, 0xa4, 0xcb, 0x6d, 0x83, 0xe7, 0xc9, 0x6d, 0x8c, 0x64, 0x8e, 0x96, 0xb1,
            0x2f, 0x4c, 0xa0, 0x32, 0x71, 0xac, 0xa0, 0xd8, 0x3e, 0x0, 0x85, 0xfa, 0x4f, 0x15,
            0xcd, 0xb8, 0x30, 0xc0, 0x5e, 0x18, 0xdf, 0x75, 0xcf, 0x79, 0x39, 0xee, 0xe9, 0xee,
            0x4c, 0x4d, 0xf9, 0x62, 0xdc, 0xbf, 0x1e, 0xe4, 0xd6, 0xb, 0x6e, 0x34, 0x42, 0x11,
            0x1d, 0xe1, 0x8b, 0x6d, 0x35, 0xd8, 0xb3, 0xbc, 0xc3, 0xf1, 0xb2, 0x8a, 0xc7, 0xe8,
            0x6c, 0xe5, 0x20, 0xd4, 0x7d, 0x19, 0xa4, 0x5d, 0xe, 0xf7, 0x42, 0xd3, 0xbf, 0xdc,
            0xeb, 0xd2, 0x3e, 0x7, 0x79, 0x93, 0x75, 0xf, 0x31, 0x70, 0x22, 0xa6, 0x12, 0x30, 0x5e,
            0x74, 0xaa, 0xa7, 0x99, 0x67, 0xe5, 0xf2, 0x86, 0xa6, 0x64, 0x38, 0x7f, 0x5a, 0x87,
            0x45, 0x52, 0x85, 0xb1, 0x1, 0x9b, 0xeb, 0x4b, 0x9f, 0x1b, 0x88, 0x94, 0x2f, 0xcc,
            0x6a, 0xe, 0x62, 0x15, 0x63, 0x4b, 0x36, 0x5c, 0xf, 0x3d, 0xa5, 0x2,
        ];
        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &truncated_sapling_data[..]),
            Err(ParseError::InvalidEncoding)
        );

        // - Truncated after the typecode of the Sapling fvk.
        let truncated_after_sapling_typecode = vec![
            0x2e, 0x15, 0x1b, 0x18, 0x5f, 0xc4, 0x1b, 0x65, 0xbb, 0xce, 0x68, 0x79, 0xf3, 0xff,
            0xd6, 0x67, 0xe7, 0x80, 0x2a, 0xa6, 0x48, 0xf5, 0xbf, 0x9e, 0xd1, 0x7e, 0xec, 0xfd,
            0x85, 0xd0, 0xb, 0x26, 0x56, 0xa8, 0x6b, 0x67, 0xff, 0x33, 0x1e, 0x1f, 0xce, 0x4, 0x24,
            0x20, 0x47, 0x31, 0xc6, 0xa1, 0xa2, 0x2d, 0xfa, 0xc4, 0x72, 0x8c, 0xa2, 0x7e, 0xc4,
            0xc7, 0x15, 0x7e, 0x98, 0x18, 0xa2, 0x77, 0x5f, 0xdf, 0x7, 0x3e, 0x7a, 0xe2, 0xe, 0xaf,
            0x4a, 0x63, 0x4c, 0xd8, 0x19, 0x6f, 0x45, 0xa4, 0x56, 0xd1, 0x6f, 0x90, 0xb3, 0x7a,
            0xac, 0x70, 0xc, 0xc3, 0x87, 0x4c, 0xf3, 0x83, 0xeb, 0x43, 0xa7, 0xf8, 0x78,
        ];
        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &truncated_after_sapling_typecode[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn duplicate_typecode() {
        // Construct and serialize an invalid UFVK.
        let ufvk = Ufvk(vec![Fvk::Sapling([1; 96]), Fvk::Sapling([2; 96])]);
        let encoded = ufvk.to_bytes(Ufvk::MAINNET);
        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &encoded[..]),
            Err(ParseError::DuplicateTypecode(Typecode::Sapling))
        );
    }

    #[test]
    fn p2pkh_and_p2sh() {
        // Construct and serialize an invalid UFVK.
        let ufvk = Ufvk(vec![Fvk::P2pkh([0; 78]), Fvk::P2sh([0; 20])]);
        let encoded = ufvk.to_bytes(Ufvk::MAINNET);
        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &encoded[..]),
            Err(ParseError::BothP2phkAndP2sh)
        );
    }

    #[test]
    fn only_transparent() {
        // Encoding of `Ufvk(vec![Fvk::P2pkh([0; 78])])`.
        let encoded = vec![
            0x86, 0xb2, 0x38, 0xf7, 0x85, 0x6e, 0xe9, 0xff, 0x80, 0xd8, 0x4e, 0x40, 0x30, 0x0, 0x2,
            0xa6, 0xdb, 0x1e, 0x89, 0x40, 0x61, 0x89, 0xdf, 0xdc, 0xc1, 0x6f, 0x2d, 0x3, 0xb8,
            0x50, 0x82, 0xd4, 0xe8, 0xb4, 0x93, 0x6a, 0x28, 0x46, 0xa8, 0xd5, 0xd9, 0x32, 0x79,
            0xb5, 0xf3, 0xb8, 0x8b, 0x9b, 0x94, 0x36, 0xf5, 0x82, 0x5a, 0xec, 0xaf, 0x30, 0x7b,
            0xbb, 0x46, 0x22, 0xcd, 0xa, 0x99, 0x28, 0x3a, 0x70, 0x63, 0xf, 0x5e, 0x61, 0xfc, 0xbb,
            0xc0, 0x68, 0x9b, 0xa0, 0xdf, 0x4b, 0x4f, 0xb1, 0xbd, 0x14, 0x50, 0xa4, 0x1b, 0xfb,
            0x40, 0xbe, 0x1b, 0xcb, 0x6b, 0x76, 0x2, 0xf2, 0x71, 0xcd,
        ];

        assert_eq!(
            Ufvk::from_bytes(Ufvk::MAINNET, &encoded[..]),
            Err(ParseError::OnlyTransparent)
        );
    }

    #[test]
    fn fvks_are_sorted() {
        // Construct a UFVK with fvks in an unsorted order.
        let ufvk = Ufvk(vec![
            Fvk::P2pkh([0; 78]),
            Fvk::Orchard([0; 96]),
            Fvk::Unknown {
                typecode: 0xff,
                data: vec![],
            },
            Fvk::Sapling([0; 96]),
        ]);

        // `Ufvk::receivers` sorts the fvks in priority order.
        assert_eq!(
            ufvk.receivers(),
            vec![
                Fvk::Orchard([0; 96]),
                Fvk::Sapling([0; 96]),
                Fvk::P2pkh([0; 78]),
                Fvk::Unknown {
                    typecode: 0xff,
                    data: vec![],
                },
            ]
        )
    }
}
