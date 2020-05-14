// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use std::io;
use crate::{errors::TwopacError, util::tweak2, Evaluator as Ev, Fancy, FancyInput, FancyReveal, Wire};
use ocelot::ot::Receiver as OtReceiver;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest, Malicious};

/// A communication channel that verifies that both parties are providing the same data.
struct VerifyEqualChannel<C1, C2> {
    channel_p1: C1,
    channel_p2: C2,
}

/// Malicious evaluator.
pub struct Evaluator<C1, C2, RNG, OT> {
    evaluator: Ev<VerifyEqualChannel<C1, C2>>,
    ot: OT,
    rng: RNG,
}

impl<C1, C2, RNG, OT> Evaluator<C1, C2, RNG, OT> {}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block>>
    Evaluator<C1, C2, RNG, OT>
{
    /// Make a new `Evaluator`.
    pub fn new(mut channel_p1: C1, channel_p2: C2, mut rng: RNG) -> Result<Self, TwopacError> {
        let ot = OT::init(&mut channel_p1, &mut rng)?;
        let channel = VerifyEqualChannel {
            channel_p1,
            channel_p2,
        };
        let evaluator = Ev::new(channel);
        Ok(Self {
            evaluator,
            ot,
            rng,
        })
    }

    // TODO: get_channel
    pub fn get_p1_channel(&mut self) -> &mut C1 {
        &mut self.evaluator.get_channel().channel_p1
    }

    pub fn get_p2_channel(&mut self) -> &mut C2 {
        &mut self.evaluator.get_channel().channel_p2
    }


    fn run_ot(&mut self, inputs: &[bool]) -> Result<Vec<Block>, TwopacError> {
        self.ot
            .receive(self.evaluator.get_channel(), &inputs, &mut self.rng)
            .map_err(TwopacError::from)
    }

    fn secret_share(&mut self, input: u16, modulus: u16) -> Result<(), TwopacError> {
        let channel_p1 = self.get_p1_channel();
        let p1 =  rand::random::<u16>();
        channel_p1.write_u16(p1)?;
        channel_p1.flush()?;

        let channel_p2 = self.get_p2_channel();
        let p2 = (p1 as u32 + input as u32) % modulus as u32;
        channel_p2.write_u16(p2 as u16)?;
        channel_p2.flush()?;

        Ok(())
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block>> FancyInput
    for Evaluator<C1, C2, RNG, OT>
{
    type Item = Wire;
    type Error = TwopacError;

    /// Receive a garbler input wire.
    fn receive(&mut self, modulus: u16) -> Result<Wire, TwopacError> {
        let block = self.evaluator.get_channel().channel_p1.read_block()?; // TODO: Maybe its from p2.
        let label = Wire::from_block(block, modulus);
        let color = label.color();

        for _ in 0..color { self.evaluator.get_channel().channel_p2.read_block()?; }
        let commitment = self.evaluator.get_channel().channel_p2.read_block()?;
        for _ in (color+1)..modulus { self.evaluator.get_channel().channel_p2.read_block()?; }

        if label.hash(tweak2(color as u64, 2)) != commitment {
            // TODO: Better errors
            return Result::Err(TwopacError::IoError(io::Error::new(io::ErrorKind::ConnectionAborted, "Wire doesn't match commitment")));
        }

        Ok(label)
    }

    /// Receive garbler input wires.
    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        moduli.iter().map(|q| self.receive(*q)).collect()
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(&mut self, inputs: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = f32::from(*q).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self.run_ot(&bs)?;
        let mut start = 0;
        Ok(lens
            .into_iter()
            .zip(moduli.iter())
            .map(|(len, q)| {
                let range = start..start + len;
                let chunk = &wires[range];
                start += len;
                combine(chunk, *q)
            })
            .collect::<Vec<Wire>>())
    }
}

fn combine(wires: &[Block], q: u16) -> Wire {
    wires.iter().enumerate().fold(Wire::zero(q), |acc, (i, w)| {
        let w = Wire::from_block(*w, q);
        acc.plus(&w.cmul(1 << i))
    })
}

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block>> Fancy for Evaluator<C1, C2, RNG, OT> {
    type Item = Wire;
    type Error = TwopacError;

    fn constant(&mut self, _: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.receive(q)
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

impl<C1: AbstractChannel, C2: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block>> FancyReveal for Evaluator<C1, C2, RNG, OT> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.evaluator.reveal(x).map_err(Self::Error::from)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel> io::Read for VerifyEqualChannel<C1, C2> {
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

impl<C1: AbstractChannel, C2: AbstractChannel> io::Write for VerifyEqualChannel<C1, C2> {
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

impl<C1: AbstractChannel, C2: AbstractChannel, RNG, OT> SemiHonest for Evaluator<C1, C2, RNG, OT> {}
impl<C1: AbstractChannel, C2: AbstractChannel, RNG, OT> Malicious for Evaluator<C1, C2, RNG, OT> {}
