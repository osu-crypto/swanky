// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use std::io;
use std::io::{Read, Write};
use crate::{errors::TwopacError, util::tweak2, Evaluator as Ev, Fancy, FancyInput, FancyReveal, threepac::malicious::PartyId, Wire};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, SemiHonest, Malicious};

/// A communication channel that verifies that both parties are providing the same data.
struct VerifyEqualChannel<C1, C2> {
    channel_p1: C1,
    channel_p2: C2,
}

/// Malicious evaluator.
pub struct Evaluator<C1, C2, RNG> {
    evaluator: Ev<VerifyEqualChannel<C1, C2>>,
    rng: RNG,
}

impl<C1, C2, RNG> Evaluator<C1, C2, RNG> {}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng>
    Evaluator<C1, C2, RNG>
{
    /// Make a new `Evaluator`.
    pub fn new(channel_p1: C1, channel_p2: C2, rng: RNG) -> Result<Self, TwopacError> {
        let channel = VerifyEqualChannel {
            channel_p1,
            channel_p2,
        };
        let evaluator = Ev::new(channel);
        Ok(Self {
            evaluator,
            rng,
        })
    }

    pub fn get_channel_p1(&mut self) -> &mut C1 {
        &mut self.evaluator.get_channel().channel_p1
    }

    pub fn get_channel_p2(&mut self) -> &mut C2 {
        &mut self.evaluator.get_channel().channel_p2
    }


    fn secret_share(&mut self, input: u16, modulus: u16) -> Result<(), TwopacError> {
        let p1: u16 =  self.rng.gen();
        let channel_p1 = self.get_channel_p1();
        channel_p1.write_u16(p1)?;

        let p2 = (p1 as u32 + input as u32) % modulus as u32;
        let channel_p2 = self.get_channel_p2();
        channel_p2.write_u16(p2 as u16)?;

        Ok(())
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng> FancyInput
    for Evaluator<C1, C2, RNG>
{
    type Item = Wire;
    type Error = TwopacError;
    type PartyId = PartyId;

    /// Receive a garbler input wire.
    fn receive(&mut self, from: PartyId, modulus: u16) -> Result<Wire, TwopacError> {
        assert!(from != PartyId::Evaluator);

        let block = if from == PartyId::Garbler1 {
            self.get_channel_p1().read_block()
        } else {
            self.get_channel_p2().read_block()
        }?;
        let label = Wire::from_block(block, modulus);
        let color = label.color();

        let mut read_commitment = || {
            if from == PartyId::Garbler1 {
                self.get_channel_p2().read_block()
            } else {
                self.get_channel_p1().read_block()
            }
        };

        for _ in 0..color { read_commitment()?; }
        let commitment = read_commitment()?;
        for _ in (color+1)..modulus { read_commitment()?; }

        if label.hash(tweak2(color as u64, 2)) != commitment {
            // TODO: Better errors
            return Result::Err(TwopacError::IoError(io::Error::new(io::ErrorKind::ConnectionAborted, "Wire doesn't match commitment")));
        }

        Ok(label)
    }

    /// Receive garbler input wires.
    fn receive_many(&mut self, from: PartyId, moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        moduli.iter().map(|q| self.receive(from, *q)).collect()
    }

    /// Obtain wires for the evaluator's inputs.
    fn encode_many(&mut self, inputs: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            self.secret_share(*x, *q)?;
        }
        self.evaluator.get_channel().flush()?;

        let wires_p1 = self.receive_many(PartyId::Garbler1, moduli)?;
        let wires_p2 = self.receive_many(PartyId::Garbler2, moduli)?;
        wires_p1
            .iter()
            .zip(wires_p2.iter())
            .map(|(w1, w2)| {
                self.evaluator.sub(w2, w1).map_err(Self::Error::from)
            })
            .collect()
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng> Fancy for Evaluator<C1, C2, RNG> {
    type Item = Wire;
    type Error = TwopacError;

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
        self.evaluator.output(&x).map_err(Self::Error::from)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng> FancyReveal for Evaluator<C1, C2, RNG> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        let output = self.output(x)?.expect("Evaluator always outputs Some(u16)");
        self.evaluator.get_channel().write_block(&x.as_block())?;
        self.evaluator.get_channel().flush()?;
        Ok(output)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel> Read for VerifyEqualChannel<C1, C2> {
    #[inline]
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.channel_p1.read(&mut bytes)?;
        let mut p2_buf = vec![0u8; bytes_read];
        self.channel_p2.read_exact(&mut p2_buf[..])?;

        // Check equality
        if bytes[..bytes_read] != p2_buf[..] {
            return Result::Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Parties 1 and 2 disagree"));
        }

        Ok(bytes_read)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel> Write for VerifyEqualChannel<C1, C2> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let bytes_written = self.channel_p1.write(bytes)?;
        self.channel_p2.write_all(&bytes[..bytes_written])?;
        Ok(bytes_written)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.channel_p1.flush()?;
        self.channel_p2.flush()
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng> SemiHonest for Evaluator<C1, C2, RNG> {}
impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng> Malicious for Evaluator<C1, C2, RNG> {}
