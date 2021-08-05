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

#[cfg(test)]
mod tests {
    use proptest::{
        array::{uniform14, uniform20, uniform32},
        prelude::*,
    };

    use super::{Ivk, ParseError, Typecode, Uivk};
    use crate::kind::unified::Unified;

    prop_compose! {
        fn uniform64()(a in uniform32(0u8..), b in uniform32(0u8..)) -> [u8; 64] {
            let mut c = [0; 64];
            c[..32].copy_from_slice(&a);
            c[32..].copy_from_slice(&b);
            c
        }
    }

    prop_compose! {
        fn uniform78()(a in uniform14(0u8..), b in uniform64()) -> [u8; 78] {
            let mut c = [0; 78];
            c[..14].copy_from_slice(&a);
            c[14..].copy_from_slice(&b);
            c
        }
    }

    fn arb_shielded_ivk() -> BoxedStrategy<Ivk> {
        prop_oneof![
            uniform64().prop_map(Ivk::Sapling),
            uniform64().prop_map(Ivk::Orchard),
        ]
        .boxed()
    }

    fn arb_transparent_ivk() -> BoxedStrategy<Ivk> {
        prop_oneof![
            uniform78().prop_map(Ivk::P2pkh),
            uniform20(0u8..).prop_map(Ivk::P2sh),
        ]
        .boxed()
    }

    prop_compose! {
        fn arb_unified_ivk()(
            shielded in prop::collection::hash_set(arb_shielded_ivk(), 1..2),
            transparent in prop::option::of(arb_transparent_ivk()),
        ) -> Uivk {
            Uivk(shielded.into_iter().chain(transparent).collect())
        }
    }

    proptest! {
        #[test]
        fn uivk_roundtrip(
            hrp in prop_oneof![Uivk::MAINNET, Uivk::TESTNET, Uivk::REGTEST],
            uivk in arb_unified_ivk(),
        ) {
            let bytes = uivk.to_bytes(&hrp);
            let decoded = Uivk::from_bytes(hrp.as_str(), &bytes[..]);
            prop_assert_eq!(decoded, Ok(uivk));
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Uivk(vec![Ivk::Orchard([1; 64])])` as base.

        // Invalid padding ([0xff; 16] instead of [b'u', 0x00, 0x00, 0x00...])
        let invalid_padding = vec![
            0xa4, 0x1a, 0x28, 0xe5, 0x1b, 0x46, 0x2d, 0x97, 0x54, 0xdd, 0x82, 0xea, 0xdf, 0x10,
            0x40, 0x71, 0x53, 0xe2, 0xf5, 0x8c, 0xf6, 0xd7, 0xad, 0x77, 0xcf, 0xe1, 0xbb, 0xd4,
            0xa7, 0x27, 0x56, 0x2c, 0x1c, 0xb7, 0x3f, 0xdb, 0x25, 0xa2, 0x51, 0xa7, 0xf6, 0xc8,
            0x48, 0x51, 0x2c, 0x4a, 0x66, 0xe2, 0xee, 0x8f, 0x8b, 0x4e, 0xa5, 0x76, 0x66, 0x92,
            0x42, 0x71, 0x23, 0x51, 0x1a, 0xa7, 0xc2, 0x12, 0x4f, 0x30, 0xae, 0x5, 0x7e, 0x7, 0x99,
            0xb6, 0x1b, 0x19, 0x44, 0xc6, 0x8b, 0x61, 0x29, 0x25, 0x89, 0xbe,
        ];
        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &invalid_padding[..]),
            Err(ParseError::InvalidEncoding)
        );

        // Short padding (padded to 15 bytes instead of 16)
        let truncated_padding = vec![
            0x15, 0x2f, 0x77, 0xd3, 0x57, 0xa7, 0x88, 0x3b, 0x81, 0xab, 0x56, 0xf9, 0x19, 0x42,
            0xd7, 0x22, 0xae, 0xc9, 0x8d, 0x82, 0x7d, 0xad, 0x14, 0x29, 0x2e, 0x5b, 0x98, 0xac,
            0xc2, 0x77, 0x7c, 0x1, 0x33, 0x4a, 0x8e, 0xa2, 0xb7, 0xff, 0x31, 0x17, 0xa2, 0x56,
            0x2d, 0x14, 0x6f, 0x6d, 0x41, 0x41, 0x1c, 0xd4, 0x99, 0xf7, 0x0, 0xb1, 0xdc, 0xfb,
            0xe5, 0xa1, 0xb2, 0x63, 0x63, 0x8, 0xee, 0x88, 0x3d, 0x73, 0x9e, 0xad, 0xba, 0x22,
            0x13, 0x8e, 0x84, 0x5e, 0x4a, 0xb6, 0x39, 0x1d, 0x3f, 0xc3, 0xe1,
        ];
        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &truncated_padding[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn truncated() {
        // The test cases below start from an encoding of
        //     `Uivk(vec![Ivk::Orchard([1; 64]), Ivk::Sapling([2; 64])])`
        // with the ivk data truncated, but valid padding.

        // - Missing the last data byte of the Sapling ivk.
        let truncated_sapling_data = vec![
            0x9, 0x4d, 0x7e, 0xbd, 0xfb, 0x52, 0xcd, 0xf0, 0xf2, 0x80, 0xc8, 0xc9, 0xad, 0x74,
            0x3a, 0xa3, 0x7f, 0x8f, 0x35, 0x1e, 0xcc, 0x29, 0x72, 0xbc, 0x16, 0x40, 0xff, 0x29,
            0x6a, 0x5f, 0xbb, 0xaa, 0x5a, 0xf, 0xed, 0x60, 0xac, 0xc3, 0x48, 0xe, 0x9d, 0x38, 0x70,
            0xcf, 0xd5, 0x11, 0x15, 0xa5, 0x22, 0xf0, 0xc0, 0xc8, 0xa2, 0x25, 0xdb, 0x2, 0xc8,
            0xf9, 0x9, 0x96, 0x11, 0x2f, 0xa3, 0x99, 0xd2, 0x11, 0x3b, 0x45, 0x14, 0xaf, 0xcd,
            0xae, 0x81, 0x27, 0xc6, 0x88, 0x7, 0xf6, 0x4f, 0x81, 0xa5, 0x15, 0x73, 0x8a, 0x74,
            0xcc, 0x7, 0x1a, 0x1d, 0x7c, 0x9f, 0x4a, 0x55, 0xda, 0xe5, 0x2a, 0x3c, 0xf7, 0xe5,
            0x1a, 0xa4, 0x1a, 0x93, 0x7d, 0x97, 0x34, 0xbb, 0x9, 0x54, 0xbe, 0xf7, 0xf8, 0x7e,
            0xe1, 0x8e, 0xb8, 0x92, 0xf2, 0x67, 0xeb, 0x66, 0xe1, 0x7d, 0xf, 0x73, 0x81, 0xdb,
            0xe0, 0x9, 0x2a, 0x42, 0xa9, 0xfc, 0x38, 0xde, 0x89, 0xfd, 0x31, 0x9d, 0x70, 0x7c, 0x2,
            0x8f, 0x13, 0x6, 0x1a, 0xcc,
        ];
        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &truncated_sapling_data[..]),
            Err(ParseError::InvalidEncoding)
        );

        // - Truncated after the typecode of the Sapling ivk.
        let truncated_after_sapling_typecode = vec![
            0x20, 0xcd, 0x21, 0x85, 0x5a, 0x20, 0x89, 0xb4, 0x3e, 0xcc, 0x5f, 0xd3, 0x8f, 0xeb,
            0xc6, 0x27, 0x74, 0x35, 0x48, 0xd6, 0x9, 0x73, 0x64, 0xf6, 0xc1, 0x20, 0x22, 0x2a,
            0xcb, 0xbf, 0xce, 0xc5, 0xe1, 0xb1, 0x14, 0xd9, 0x4a, 0x3c, 0xba, 0x2d, 0xe8, 0x42,
            0xf3, 0x7a, 0xd, 0x7a, 0x4f, 0xa4, 0x4c, 0xb, 0x67, 0xd, 0x92, 0x71, 0x7, 0xdc, 0xf7,
            0x7f, 0x3a, 0x1e, 0xb0, 0x6, 0xda, 0xa1, 0x49, 0xfe, 0x79,
        ];
        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &truncated_after_sapling_typecode[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn duplicate_typecode() {
        // Construct and serialize an invalid UIVK.
        let uivk = Uivk(vec![Ivk::Sapling([1; 64]), Ivk::Sapling([2; 64])]);
        let encoded = uivk.to_bytes(Uivk::MAINNET);
        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &encoded[..]),
            Err(ParseError::DuplicateTypecode(Typecode::Sapling))
        );
    }

    #[test]
    fn p2pkh_and_p2sh() {
        // Construct and serialize an invalid UIVK.
        let uivk = Uivk(vec![Ivk::P2pkh([0; 78]), Ivk::P2sh([0; 20])]);
        let encoded = uivk.to_bytes(Uivk::MAINNET);
        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &encoded[..]),
            Err(ParseError::BothP2phkAndP2sh)
        );
    }

    #[test]
    fn only_transparent() {
        // Encoding of `Uivk(vec![Ivk::P2pkh([0; 78])])`.
        let encoded = vec![
            0x47, 0xde, 0x1e, 0xc8, 0xaf, 0x31, 0x70, 0xc8, 0xe0, 0x24, 0x6, 0xa9, 0x56, 0x0, 0x6,
            0x7c, 0xeb, 0xe9, 0xa, 0x9, 0x2f, 0xde, 0xe7, 0x80, 0xff, 0x83, 0xf0, 0x8f, 0x56, 0x7b,
            0xc9, 0x18, 0xa3, 0x96, 0x93, 0x98, 0xc, 0xab, 0xf9, 0xce, 0x98, 0xfc, 0x1b, 0xc7,
            0xdb, 0x90, 0x41, 0x2e, 0xb5, 0x71, 0x3f, 0xa3, 0xaa, 0xe0, 0xa3, 0xd1, 0xce, 0xdf,
            0x4f, 0x6c, 0x7c, 0xec, 0x95, 0x9, 0x95, 0xc8, 0xb9, 0x56, 0x8f, 0xf9, 0x3, 0x98, 0xaf,
            0x2e, 0xe3, 0xdb, 0xb0, 0x69, 0x19, 0x30, 0x71, 0xa6, 0x65, 0x0, 0x7, 0xef, 0x5, 0x65,
            0x8f, 0x9c, 0x80, 0xb2, 0xc6, 0x88, 0xa5, 0x85,
        ];

        assert_eq!(
            Uivk::from_bytes(Uivk::MAINNET, &encoded[..]),
            Err(ParseError::OnlyTransparent)
        );
    }

    #[test]
    fn ivks_are_sorted() {
        // Construct a UIVK with ivks in an unsorted order.
        let uivk = Uivk(vec![
            Ivk::P2pkh([0; 78]),
            Ivk::Orchard([0; 64]),
            Ivk::Unknown {
                typecode: 0xff,
                data: vec![],
            },
            Ivk::Sapling([0; 64]),
        ]);

        // `Uivk::receivers` sorts the ivks in priority order.
        assert_eq!(
            uivk.receivers(),
            vec![
                Ivk::Orchard([0; 64]),
                Ivk::Sapling([0; 64]),
                Ivk::P2pkh([0; 78]),
                Ivk::Unknown {
                    typecode: 0xff,
                    data: vec![],
                },
            ]
        )
    }
}
