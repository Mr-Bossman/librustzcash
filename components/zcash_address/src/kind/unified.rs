use std::{cmp, collections::HashSet, convert::TryFrom, error::Error, fmt, iter};

pub(crate) mod address;
mod f4jumble;

pub(crate) use address::Address;

const PADDING_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    P2pkh,
    P2sh,
    Sapling,
    Orchard,
    Unknown(u8),
}

impl Ord for Typecode {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            // Trivial equality checks.
            (Self::Orchard, Self::Orchard)
            | (Self::Sapling, Self::Sapling)
            | (Self::P2sh, Self::P2sh)
            | (Self::P2pkh, Self::P2pkh) => cmp::Ordering::Equal,

            // We don't know for certain the preference order of unknown receivers, but it
            // is likely that the higher typecode has higher preference. The exact order
            // doesn't really matter, as unknown receivers have lower preference than
            // known receivers.
            (Self::Unknown(a), Self::Unknown(b)) => b.cmp(a),

            // For the remaining cases, we rely on `match` always choosing the first arm
            // with a matching pattern. Patterns below are listed in priority order:
            (Self::Orchard, _) => cmp::Ordering::Less,
            (_, Self::Orchard) => cmp::Ordering::Greater,

            (Self::Sapling, _) => cmp::Ordering::Less,
            (_, Self::Sapling) => cmp::Ordering::Greater,

            (Self::P2sh, _) => cmp::Ordering::Less,
            (_, Self::P2sh) => cmp::Ordering::Greater,

            (Self::P2pkh, _) => cmp::Ordering::Less,
            (_, Self::P2pkh) => cmp::Ordering::Greater,
        }
    }
}

impl PartialOrd for Typecode {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u8> for Typecode {
    fn from(typecode: u8) -> Self {
        match typecode {
            0x00 => Typecode::P2pkh,
            0x01 => Typecode::P2sh,
            0x02 => Typecode::Sapling,
            0x03 => Typecode::Orchard,
            _ => Typecode::Unknown(typecode),
        }
    }
}

impl From<Typecode> for u8 {
    fn from(t: Typecode) -> Self {
        match t {
            Typecode::P2pkh => 0x00,
            Typecode::P2sh => 0x01,
            Typecode::Sapling => 0x02,
            Typecode::Orchard => 0x03,
            Typecode::Unknown(typecode) => typecode,
        }
    }
}

impl Typecode {
    fn is_transparent(&self) -> bool {
        // Unknown typecodes are treated as not transparent for the purpose of disallowing
        // only-transparent UAs, which can be represented with existing address encodings.
        matches!(self, Typecode::P2pkh | Typecode::P2sh)
    }
}

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The unified address contains both P2PKH and P2SH receivers.
    BothP2phkAndP2sh,
    /// The unified address contains a duplicated typecode.
    DuplicateTypecode(Typecode),
    /// The string is an invalid encoding.
    InvalidEncoding,
    /// The unified address only contains transparent receivers.
    OnlyTransparent,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BothP2phkAndP2sh => write!(f, "UA contains both P2PKH and P2SH receivers"),
            ParseError::DuplicateTypecode(typecode) => {
                write!(f, "Duplicate typecode {}", u8::from(*typecode))
            }
            ParseError::InvalidEncoding => write!(f, "Invalid encoding"),
            ParseError::OnlyTransparent => write!(f, "UA only contains transparent receivers"),
        }
    }
}

impl Error for ParseError {}

mod private {
    use super::{ParseError, Typecode};
    use std::{cmp, convert::TryFrom};

    /// A raw address or viewing key.
    pub trait Receiver:
        TryFrom<(u8, Vec<u8>), Error = ParseError> + cmp::Ord + cmp::PartialOrd + Clone
    {
        fn typecode(&self) -> Typecode;
        fn data(&self) -> &[u8];
    }

    pub trait Sealed {
        type Receiver: Receiver;
        fn from_inner(receivers: Vec<Self::Receiver>) -> Self;
    }
}

use private::Receiver;

/// Trait providing common encoding logic for Unified containers.
pub trait Unified: private::Sealed + std::marker::Sized {
    const MAINNET: &'static str;
    const TESTNET: &'static str;
    const REGTEST: &'static str;

    /// TODO
    fn from_bytes(hrp: &str, buf: &[u8]) -> Result<Self, ParseError> {
        let encoded = f4jumble::f4jumble_inv(buf).ok_or(ParseError::InvalidEncoding)?;

        // Validate and strip trailing padding bytes.
        if hrp.len() > 16 {
            return Err(ParseError::InvalidEncoding);
        }
        let mut expected_padding = vec![0; PADDING_LEN];
        expected_padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
        let encoded = match encoded.split_at(encoded.len() - PADDING_LEN) {
            (encoded, tail) if tail == expected_padding => Ok(encoded),
            _ => Err(ParseError::InvalidEncoding),
        }?;

        iter::repeat(())
            .scan(encoded, |encoded, _| match encoded {
                // Base case: we've parsed the full encoding.
                [] => None,
                // The raw encoding of a Unified Address is a concatenation of:
                // - typecode: byte
                // - length: byte
                // - addr: byte[length]
                [typecode, length, data @ ..] if data.len() >= *length as usize => {
                    let (addr, rest) = data.split_at(*length as usize);
                    *encoded = rest;
                    Some(Self::Receiver::try_from((*typecode, addr.to_vec())))
                }
                // The encoding is truncated.
                _ => Some(Err(ParseError::InvalidEncoding)),
            })
            .collect::<Result<_, _>>()
            .and_then(Self::try_from_receivers)
    }

    fn try_from_receivers(receivers: Vec<Self::Receiver>) -> Result<Self, ParseError> {
        let mut typecodes = HashSet::with_capacity(receivers.len());
        for receiver in &receivers {
            let t = receiver.typecode();
            if typecodes.contains(&t) {
                return Err(ParseError::DuplicateTypecode(t));
            } else if (t == Typecode::P2pkh && typecodes.contains(&Typecode::P2sh))
                || (t == Typecode::P2sh && typecodes.contains(&Typecode::P2pkh))
            {
                return Err(ParseError::BothP2phkAndP2sh);
            } else {
                typecodes.insert(t);
            }
        }

        if typecodes.iter().all(|t| t.is_transparent()) {
            Err(ParseError::OnlyTransparent)
        } else {
            // All checks pass!
            Ok(Self::from_inner(receivers))
        }
    }

    /// Returns the raw encoding of this Unified Address or viewing key.
    fn to_bytes(&self, hrp: &str) -> Vec<u8> {
        assert!(hrp.len() <= 16);

        let encoded: Vec<_> = self
            .receivers_as_parsed()
            .iter()
            .flat_map(|receiver| {
                let data = receiver.data();
                // Holds by construction.
                assert!(data.len() < 256);

                iter::empty()
                    .chain(Some(receiver.typecode().into()))
                    .chain(Some(data.len() as u8))
                    .chain(data.iter().cloned())
            })
            .chain(hrp.as_bytes().iter().cloned())
            .chain(iter::repeat(0).take(PADDING_LEN - hrp.len()))
            .collect();

        f4jumble::f4jumble(&encoded).unwrap()
    }

    /// Returns the receivers contained within this unified encoding, sorted in preference order.
    fn receivers(&self) -> Vec<Self::Receiver> {
        let mut receivers = self.receivers_as_parsed().to_vec();
        // Unstable sorting is fine, because all receivers are guaranteed by construction
        // to have distinct typecodes.
        receivers.sort_unstable_by_key(|r| r.typecode());
        receivers
    }

    /// Returns the receivers in the order they were parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Self::receivers`.
    fn receivers_as_parsed(&self) -> &[Self::Receiver];
}
