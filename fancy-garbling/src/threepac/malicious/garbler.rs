// -*- mode: rust; -*-
//
// This file is part of threepac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{errors::{GarblerError, FancyError}, util::tweak2, Fancy, FancyInput, FancyReveal, HasModulus, Garbler as Gb, threepac::malicious::PartyId, Wire};
use digest::{FixedOutput, Input, Reset};
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest, Malicious, UniversalDigest};
use std::cmp::min;
use std::io;
use std::io::{Read, Write};
use std::slice::from_ref;
use universal_hash::{generic_array::GenericArray, UniversalHash};

struct AlternatingHashChannel<C, H> {
    channel: C,
    hash: H,

    alternate_every: usize,
    bytes_hashed: usize,
}

/// Honest majority three party garbler.
pub struct Garbler<C, RNG, H: UniversalHash> {
    garbler: Gb<AlternatingHashChannel<C, UniversalDigest<H>>, RNG>,
    party: PartyId,
}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
        H: UniversalHash,
    > Garbler<C, RNG, H>
{
    /// Make a new `Garbler`. The protocol calls for two `Garblers`, which take turns sending the
    /// garbled circuit to the evaluator, switching places every `alternate_every` bytes.
    /// `alternate_every` must match between all 3 parties.
    pub fn new<CG: AbstractChannel>(party: PartyId, channel_garblers : &mut CG, channel_evaluator: C, mut rng: RNG, alternate_every: usize) -> Result<Self, Error> {
        assert!(party != PartyId::Evaluator);

        let hash_channel = AlternatingHashChannel::new(channel_evaluator, &mut rng, alternate_every, party)?;

        let seed: Block;
        if party == PartyId::Garbler1 {
            seed = rng.gen();
            channel_garblers.write_block(&seed)?;
            channel_garblers.flush()?;
        } else {
            seed = channel_garblers.read_block()?;
        }

        let garbler = Gb::new(hash_channel, RNG::from_seed(seed));

        Ok(Garbler {
            garbler,
            party,
        })
    }
}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
        H: UniversalHash,
    > Garbler<C, RNG, H>
{
    pub fn get_channel(&mut self) -> &mut C {
        &mut self.get_hash_channel().channel
    }

    fn get_hash_channel(&mut self) -> &mut AlternatingHashChannel<C, UniversalDigest<H>> {
        self.garbler.get_channel()
    }

    // Commit to all wire labels. Order by color to avoid leaking which label has which value.
    fn send_commitments(&mut self, zero: &Wire) -> Result<(), Error> {
        let q = zero.modulus();
        let delta = self.garbler.delta(q);
        let mut label = zero.minus(&delta.cmul(zero.color()));
        for i in 0..q {
            self.get_hash_channel().write_block(&label.hash(tweak2(i as u64, 2)))?;
            label = label.plus_mov(&delta);
        }

        Ok(())
    }
}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
        H: UniversalHash,
    > FancyInput for Garbler<C, RNG, H>
{
    type Item = Wire;
    type Error = Error;
    type PartyId = PartyId;

    fn encode_many(&mut self, vals: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, Error> {
        let ws = vals
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| {
                let (zero, theirs) = self.garbler.encode_wire(*x, *q);
                self.get_channel().write_block(&theirs.as_block())?;
                Ok(zero)
            })
            .collect::<Result<Vec<Wire>, Error>>()?;

        // Make sure the other garbler's commitments to all wire labels are correct.
        for zero in ws.iter() {
            self.send_commitments(&zero)?;
        }

        self.get_hash_channel().send_hash()?;

        Ok(ws)
    }

    fn receive_many(&mut self, from: PartyId, qs: &[u16]) -> Result<Vec<Wire>, Error> {
        assert!(from != self.party);

        if from == PartyId::Evaluator {
            self.get_hash_channel().flush()?;
            let shares = qs.iter().map(|_q|
                self.get_channel().read_u16().map_err(Self::Error::from)
            ).collect::<Result<Vec<u16>, Error>>()?;

            let (wires1, wires2);
            if self.party == PartyId::Garbler1 {
                wires1 = self.encode_many(&shares, qs)?;
                wires2 = self.receive_many(PartyId::Garbler2, qs)?;
            } else {
                wires1 = self.receive_many(PartyId::Garbler1, qs)?;
                wires2 = self.encode_many(&shares, qs)?;
            }
            let wires = wires1.iter()
                .zip(wires2.iter())
                .map(|(w1, w2)| self.garbler.sub(w2, w1).map_err(Self::Error::from))
                .collect::<Result<Vec<Wire>, Error>>()?;
            Ok(wires)
        } else {
            let wires = qs.iter().map(|q| {
                let zero = self.garbler.create_wire(*q);
                self.send_commitments(&zero)?;
                Ok(zero)
            }).collect::<Result<Vec<Wire>, Error>>()?;

            self.get_hash_channel().send_hash()?;

            Ok(wires)
        }
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash, > Fancy for Garbler<C, RNG, H> {
    type Item = Wire;
    type Error = Error;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        Ok(self.garbler.delta(q).negate_mov().cmul_mov(x))
    }

    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.add(x, y).map_err(Self::Error::from)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.sub(x, y).map_err(Self::Error::from)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.garbler.cmul(x, c).map_err(Self::Error::from)
    }

    fn mul(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.mul(x, y).map_err(Self::Error::from)
    }

    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        self.garbler.proj(x, q, tt).map_err(Self::Error::from)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        let out = self.garbler.output(x)?;
        self.get_hash_channel().send_hash()?;
        Ok(out)
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash, > FancyReveal for Garbler<C, RNG, H> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        Ok(self.reveal_many(from_ref(x))?[0])
    }

    fn reveal_many(&mut self, xs: &[Self::Item]) -> Result<Vec<u16>, Self::Error> {
        for x in xs.iter() {
            self.garbler.output(x)?;
        }

        self.get_hash_channel().send_hash()?;
        self.get_hash_channel().flush()?;

        xs.iter()
            .map(|x| {
                let q = x.modulus();
                let eval_wire = Wire::from_block(self.get_channel().read_block()?, x.modulus());
                let output =
                    ((q as u32 + eval_wire.color() as u32 - x.color() as u32) % q as u32) as u16;

                // Check that the wire label is correct
                if self.garbler.delta(q).cmul_mov(output).plus_mov(x) != eval_wire {
                    return Err(Error::InvalidResult);
                }

                Ok(output)
            })
            .collect()
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> SemiHonest for Garbler<C, RNG, H> {}
impl<C: AbstractChannel, RNG: CryptoRng + Rng, H: UniversalHash> Malicious for Garbler<C, RNG, H> {}

impl<C: AbstractChannel, H: UniversalHash> AlternatingHashChannel<C, UniversalDigest<H>> {
    fn new<RNG: CryptoRng + Rng>(mut channel: C, rng: &mut RNG, alternate_every: usize, party: PartyId) -> Result<Self, Error> {
        let mut hash_key = GenericArray::default();
        rng.fill(hash_key.as_mut_slice());
        channel.write_all(&hash_key)?;
        channel.flush()?;

        Ok(AlternatingHashChannel {
            channel,
            hash: UniversalDigest::new(&hash_key),
            alternate_every,
            bytes_hashed: if party == PartyId::Garbler1 { alternate_every } else { 0 },
        })
    }
}

impl<C: AbstractChannel, H: Clone + FixedOutput + Reset> AlternatingHashChannel<C, H> {
    fn send_hash(&mut self) -> Result<(), Error> {
        self.channel.write_all(&self.hash.clone().fixed_result())?;
        self.hash.reset();
        Ok(())
    }
}

impl<C: AbstractChannel, H: Input> Read for AlternatingHashChannel<C, H> {
    #[inline]
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        self.channel.read(&mut bytes)
    }
}

impl<C: AbstractChannel, H: Input> Write for AlternatingHashChannel<C, H> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes_hashed < self.alternate_every {
            let len = min(self.alternate_every - self.bytes_hashed, bytes.len());
            self.hash.input(&bytes[..len]);

            self.bytes_hashed += len;
            Ok(len)
        } else {
            let len = min(2*self.alternate_every - self.bytes_hashed, bytes.len());
            let bytes_written = self.channel.write(&bytes[..len])?;

            self.bytes_hashed += bytes_written;
            if self.bytes_hashed == 2*self.alternate_every { self.bytes_hashed = 0 }
            Ok(bytes_written)
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

/// Errors produced by `threepac` Garbler.
#[derive(Debug)]
pub enum Error {
    /// An I/O error has occurred.
    IoError(std::io::Error),
    /// The underlying garbler produced an error.
    GarblerError(GarblerError),
    /// Processing the garbled circuit produced an error.
    FancyError(FancyError),
    /// Evaluator may be malicious!!!
    InvalidResult,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<GarblerError> for Error {
    fn from(e: GarblerError) -> Error {
        Error::GarblerError(e)
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
            Error::GarblerError(e) => write!(f, "garbler error: {}", e),
            Error::FancyError(e) => write!(f, "fancy error: {}", e),
            Error::InvalidResult => write!(f, "evaluator sent invalid output wire label"),
        }
    }
}

impl std::error::Error for Error {}
