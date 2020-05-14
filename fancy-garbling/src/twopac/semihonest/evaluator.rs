// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{errors::TwopacError, Evaluator as Ev, Fancy, FancyInput, FancyReveal, twopac::PartyId, Wire};
use ocelot::ot::Receiver as OtReceiver;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};

/// Semi-honest evaluator.
pub struct Evaluator<C, RNG, OT> {
    evaluator: Ev<C>,
    ot: OT,
    rng: RNG,
}

impl<C, RNG, OT> Evaluator<C, RNG, OT> {}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest>
    Evaluator<C, RNG, OT>
{
    /// Make a new `Evaluator`.
    pub fn new(mut channel: C, mut rng: RNG) -> Result<Self, TwopacError> {
        let ot = OT::init(&mut channel, &mut rng)?;
        let evaluator = Ev::new(channel);
        Ok(Self {
            evaluator,
            ot,
            rng,
        })
    }

    /// Get a reference to the internal channel.
    pub fn get_channel(&mut self) -> &mut C {
        self.evaluator.get_channel()
    }

    fn run_ot(&mut self, inputs: &[bool]) -> Result<Vec<Block>, TwopacError> {
        self.ot
            .receive(self.evaluator.get_channel(), &inputs, &mut self.rng)
            .map_err(TwopacError::from)
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest> FancyInput
    for Evaluator<C, RNG, OT>
{
    type Item = Wire;
    type Error = TwopacError;
    type PartyId = PartyId;

    /// Receive a garbler input wire.
    fn receive(&mut self, from: PartyId, modulus: u16) -> Result<Wire, TwopacError> {
        assert!(from == PartyId::Garbler);
        let w = self.evaluator.read_wire(modulus)?;
        Ok(w)
    }

    /// Receive garbler input wires.
    fn receive_many(&mut self, from: PartyId, moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        assert!(from == PartyId::Garbler);
        moduli.iter().map(|q| self.receive(from, *q)).collect()
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

impl<C: AbstractChannel, RNG, OT> Fancy for Evaluator<C, RNG, OT> {
    type Item = Wire;
    type Error = TwopacError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.constant(x, q).map_err(Self::Error::from)
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

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT> FancyReveal for Evaluator<C, RNG, OT> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.evaluator.reveal(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG, OT> SemiHonest for Evaluator<C, RNG, OT> {}
