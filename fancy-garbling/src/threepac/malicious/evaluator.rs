// -*- mode: rust; -*-
//
// This file is part of threepac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{errors::{EvaluatorError, FancyError}, util::tweak2, Evaluator as Ev, Fancy, FancyInput, FancyReveal, threepac::malicious::PartyId, Wire};
use digest::{FixedOutput, Input, Reset};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest, Malicious, UniversalDigest};
use std::cmp::min;
use std::io;
use std::io::{Read, Write};
use std::slice::from_ref;
use universal_hash::{generic_array::{ArrayLength, GenericArray}, UniversalHash};

struct HashedRead<C, H> {
    channel: C,
    hash: H,
}

/// A communication channel that verifies that both parties are providing the same data.
struct VerifyChannel<C1, C2, H: UniversalHash> {
    channel_p1: HashedRead<C1, UniversalDigest<H>>,
    channel_p2: HashedRead<C2, UniversalDigest<H>>,

    alternate_every: usize,
    bytes_hashed: usize,
}

/// Honest majority three party evaluator.
pub struct Evaluator<C1, C2, RNG, H: UniversalHash> {
    evaluator: Ev<VerifyChannel<C1, C2, H>>,
    rng: RNG,
}

impl<C1, C2, RNG, H: UniversalHash> Evaluator<C1, C2, RNG, H> {}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash>
    Evaluator<C1, C2, RNG, H>
{
    /// Make a new `Evaluator`. The protocol calls for two `Garblers`, which are parties 1 and 2.
    /// They take turns sending the garbled circuit to party 3, the evaluator, switching places
    /// every `alternate_every` bytes. `alternate_every` must match between all 3 parties.
    pub fn new(channel_p1: C1, channel_p2: C2, rng: RNG, alternate_every: usize) -> Result<Self, Error> {
        let channel = VerifyChannel::new(channel_p1, channel_p2, alternate_every)?;
        let evaluator = Ev::new(channel);
        Ok(Self {
            evaluator,
            rng,
        })
    }

    /// Get communication channel with Garbler 1
    pub fn get_channel_p1(&mut self) -> &mut C1 {
        &mut self.evaluator.get_channel().channel_p1.channel
    }

    /// Get communication channel with Garbler 2
    pub fn get_channel_p2(&mut self) -> &mut C2 {
        &mut self.evaluator.get_channel().channel_p2.channel
    }


    /// Secret share Evaluator input among Garbler 1 and 2.
    fn secret_share(&mut self, input: u16, modulus: u16) -> Result<(), Error> {
        let p1: u16 =  self.rng.gen();
        let channel_p1 = self.get_channel_p1();
        channel_p1.write_u16(p1)?;

        let p2 = (p1 as u32 + input as u32) % modulus as u32;
        let channel_p2 = self.get_channel_p2();
        channel_p2.write_u16(p2 as u16)?;

        Ok(())
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> FancyInput
    for Evaluator<C1, C2, RNG, H>
{
    type Item = Wire;
    type Error = Error;
    type PartyId = PartyId;

    /// Receive garbler input wires.
    fn receive_many(&mut self, from: PartyId, moduli: &[u16]) -> Result<Vec<Wire>, Error> {
        assert!(from != PartyId::Evaluator);

        let labels = moduli.iter().map(|q| {
            let block = if from == PartyId::Garbler1 {
                self.get_channel_p1().read_block()
            } else {
                self.get_channel_p2().read_block()
            }?;
            Ok(Wire::from_block(block, *q))
        }).collect::<Result<Vec<Wire>, Error>>()?;

        let commitments = labels.iter().zip(moduli.iter()).map(|(label, q)|
            Ok(self.evaluator.get_channel().read_blocks(*q as usize)?[label.color() as usize])
        ).collect::<Result<Vec<Block>, Error>>()?;

        // Make sure that we don't leak when one garbler sends some invalid commitments.
        self.evaluator.get_channel().check_hashes()?;

        for (label, commitment) in labels.iter().zip(commitments.iter()) {
            if label.hash(tweak2(label.color() as u64, 2)) != *commitment {
                return Err(Error::InvalidCommitment);
            }
        }

        Ok(labels)
    }

    /// Obtain wires for the evaluator's inputs.
    fn encode_many(&mut self, inputs: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, Error> {
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            self.secret_share(*x, *q)?;
        }
        self.evaluator.get_channel().flush()?;

        let wires_p1 = self.receive_many(PartyId::Garbler1, moduli)?;
        let wires_p2 = self.receive_many(PartyId::Garbler2, moduli)?;
        wires_p1
            .iter()
            .zip(wires_p2.iter())
            .map(|(w1, w2)| self.evaluator.sub(w2, w1).map_err(Self::Error::from))
            .collect()
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> Fancy for Evaluator<C1, C2, RNG, H> {
    type Item = Wire;
    type Error = Error;

    fn constant(&mut self, _: u16, q: u16) -> Result<Self::Item, Self::Error> {
        Ok(Wire::zero(q))
    }

    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.add(&x, &y).map_err(Self::Error::from)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.sub(&x, &y).map_err(Self::Error::from)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.cmul(&x, c).map_err(Self::Error::from)
    }

    fn mul(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.mul(&x, &y).map_err(Self::Error::from)
    }

    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        self.evaluator.proj(&x, q, tt).map_err(Self::Error::from)
    }

    fn output(&mut self, x: &Wire) -> Result<Option<u16>, Self::Error> {
        let out = self.evaluator.output(&x)?;
        self.evaluator.get_channel().check_hashes()?;
        Ok(out)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> FancyReveal for Evaluator<C1, C2, RNG, H> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        Ok(self.reveal_many(from_ref(x))?[0])
    }

    fn reveal_many(&mut self, xs: &[Self::Item]) -> Result<Vec<u16>, Self::Error> {
        let outputs = xs
            .iter()
            .map(|x| Ok(self.evaluator.output(x)?.expect("Evaluator always outputs Some(u16)")))
            .collect::<Result<Vec<u16>, Self::Error>>()?;
        self.evaluator.get_channel().check_hashes()?;

        for x in xs.iter() {
            self.evaluator.get_channel().write_block(&x.as_block())?;
        }

        self.evaluator.get_channel().flush()?;
        Ok(outputs)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> SemiHonest for Evaluator<C1, C2, RNG, H> {}
impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> Malicious for Evaluator<C1, C2, RNG, H> {}

impl<C: AbstractChannel, H: Clone + FixedOutput + Reset> HashedRead<C, H> {
    fn compute_hash(&mut self) -> GenericArray<u8, H::OutputSize> {
        let hash = self.hash.clone().fixed_result();
        self.hash.reset();
        hash
    }
}

impl<C: AbstractChannel, H> HashedRead<C, H> {
    fn read_hash<Size: ArrayLength<u8>>(&mut self) -> io::Result<GenericArray<u8, Size>> {
        let mut hash = GenericArray::default();
        self.channel.read_exact(&mut hash)?;
        Ok(hash)
    }
}

impl<C: AbstractChannel, H: Input> Read for HashedRead<C, H> {
    #[inline]
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.channel.read(&mut bytes)?;
        self.hash.input(&bytes[..bytes_read]);
        Ok(bytes_read)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, H: UniversalHash> VerifyChannel<C1, C2, H> {
    fn new(mut channel_p1: C1, mut channel_p2: C2, alternate_every: usize) -> Result<Self, Error> {
        let mut hash_key1 = GenericArray::default();
        let mut hash_key2 = GenericArray::default();
        // Each party generates the seed that will hash the other party's data, protecting the seed
        // from the party it checks.
        channel_p1.read_exact(&mut hash_key2)?;
        channel_p2.read_exact(&mut hash_key1)?;

        Ok(VerifyChannel {
            channel_p1: HashedRead { channel: channel_p1, hash: UniversalDigest::new(&hash_key1) },
            channel_p2: HashedRead { channel: channel_p2, hash: UniversalDigest::new(&hash_key2) },
            alternate_every,
            bytes_hashed: 0,
        })
    }

    fn check_hashes(&mut self) -> Result<(), Error> {
        if self.channel_p1.read_hash()? != self.channel_p2.compute_hash() ||
           self.channel_p2.read_hash()? != self.channel_p1.compute_hash() {
            return Err( Error::GarblerMismatch);
        }
        Ok(())
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, H: UniversalHash> Read for VerifyChannel<C1, C2, H> {
    #[inline]
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let bytes_read;
        if self.bytes_hashed < self.alternate_every {
            let len = min(self.alternate_every - self.bytes_hashed, bytes.len());
            bytes_read = self.channel_p1.read(&mut bytes[..len])?;
        } else {
            let len = min(2*self.alternate_every - self.bytes_hashed, bytes.len());
            bytes_read = self.channel_p2.read(&mut bytes[..len])?;
        }

        self.bytes_hashed += bytes_read;
        if self.bytes_hashed == 2*self.alternate_every { self.bytes_hashed = 0 }
        Ok(bytes_read)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, H: UniversalHash> Write for VerifyChannel<C1, C2, H> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let bytes_written = self.channel_p1.channel.write(bytes)?;
        self.channel_p2.channel.write_all(&bytes[..bytes_written])?;
        Ok(bytes_written)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.channel_p1.channel.flush()?;
        self.channel_p2.channel.flush()
    }
}

/// Errors produced by `threepac` Evaluator.
#[derive(Debug)]
pub enum Error {
    /// An I/O error has occurred.
    IoError(io::Error),
    /// The underlying garbler produced an error.
    EvaluatorError(EvaluatorError),
    /// Processing the garbled circuit produced an error.
    FancyError(FancyError),
    /// Garbler may be malicious!!!
    GarblerMismatch,
    InvalidCommitment,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<EvaluatorError> for Error {
    fn from(e: EvaluatorError) -> Error {
        Error::EvaluatorError(e)
    }
}

impl From<FancyError> for Error {
    fn from(e: FancyError) -> Error {
        Error::FancyError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::EvaluatorError(e) => write!(f, "evaluator error: {}", e),
            Error::FancyError(e) => write!(f, "fancy error: {}", e),
            Error::GarblerMismatch => write!(f, "garbler disagree over the circuit"),
            Error::InvalidCommitment => write!(f, "garbler did not decommit correctly"),
        }
    }
}

impl std::error::Error for Error {}
