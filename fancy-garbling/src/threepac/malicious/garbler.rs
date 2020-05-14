// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{errors::TwopacError, util::tweak2, Fancy, FancyInput, FancyReveal, Garbler as Gb, Wire};
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest, Malicious};

/// Semi-honest garbler.
pub struct Garbler<C3, RNG> {
    garbler: Gb<C3, RNG>,
    is_p2: bool,
}

impl<C3, RNG> std::ops::Deref for Garbler<C3, RNG> {
    type Target = Gb<C3, RNG>;
    fn deref(&self) -> &Self::Target {
        &self.garbler
    }
}

impl<C3, RNG> std::ops::DerefMut for Garbler<C3, RNG> {
    fn deref_mut(&mut self) -> &mut Gb<C3, RNG> {
        &mut self.garbler
    }
}

impl<
        C3: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
    > Garbler<C3, RNG>
{
    /// Make a new `Garbler`.
    pub fn new<C12: AbstractChannel>(is_p2: bool, mut channel_p1_p2: C12, mut channel_p3: C3, mut rng: RNG) -> Result<Self, TwopacError> {
        let seed: Block;

        if is_p2 {
            seed = channel_p1_p2.read_block()?;
        } else {
            seed = rng.gen();
            channel_p1_p2.write_block(&seed)?;
        }

        let garbler = Gb::new(channel_p3, RNG::from_seed(seed));

        Ok(Garbler {
            garbler,
            is_p2,
        })
    }

    pub fn get_channel(&mut self) -> &mut C3 {
        self.garbler.get_channel()
    }

    /// Create a wire label when the other garbler has the input.
    pub fn declare_input(&mut self, modulus: u16) -> Result<Wire, TwopacError> {
        let zero = self.declare_input_no_flush(modulus)?;
        self.garbler.get_channel().flush()?;
        Ok(zero)
    }

    fn declare_input_no_flush(&mut self, modulus: u16) -> Result<Wire, TwopacError> {
        let zero = self.garbler.create_wire(modulus);
        let delta = self.delta(modulus);

        // Commit to all wire labels. Order by color to avoid leaking which label has which value.
        let mut label = zero.minus(&delta.cmul(zero.color()));
        for i in 0..modulus {
            self.garbler.get_channel().write_block(&label.hash(tweak2(i as u64, 2)))?;
            label = label.plus_mov(&delta);
        }
        Ok(zero)
    }

    fn _evaluator_input(&mut self, delta: &Wire, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let len = f32::from(q).log(2.0).ceil() as u16;
        let mut wire = Wire::zero(q);
        let inputs = (0..len)
            .map(|i| {
                let zero = self.garbler.create_wire(q);
                let one = zero.plus(&delta);
                wire = wire.plus(&zero.cmul(1 << i));
                (zero.as_block(), one.as_block())
            })
            .collect::<Vec<(Block, Block)>>();
        (wire, inputs)
    }

}

impl<
        C3: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
    > FancyInput for Garbler<C3, RNG>
{
    type Item = Wire;
    type Error = TwopacError;

    fn encode_many(&mut self, vals: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let ws = vals
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| {
                let (mine, theirs) = self.garbler.encode_wire(*x, *q);
                self.garbler.send_wire(&theirs)?;
                Ok(mine)
            })
            .collect();
        self.garbler.get_channel().flush()?;
        ws
    }

    fn receive_many(&mut self, qs: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let shares = qs.iter().map(|q| {
            self.garbler.get_channel().read_u16().map_err(Self::Error::from)
        }).collect::<Result<Vec<u16>, TwopacError>>()?;

        let (wires1, wires2) = if !self.is_p2 {
            let wires1 = self.encode_many(&shares, qs)?;
            let wires2 = qs.iter().map(|q| { self.declare_input(*q) }).collect::<Result<Vec<Wire>, TwopacError>>()?;
            (wires1, wires2)
        } else {
            let wires1 = qs.iter().map(|q| { self.declare_input(*q) }).collect::<Result<Vec<Wire>, TwopacError>>()?;
            let wires2 = self.encode_many(&shares, qs)?;
            (wires1, wires2)
        };
        let wires = wires1.iter()
            .zip(wires2.iter())
            .map(|(w1, w2)| {
                self.garbler.sub(w2, w1).map_err(Self::Error::from)
            })
            .collect::<Result<Vec<Wire>, TwopacError>>()?;
        Ok(wires)
    }
}

impl<C3: AbstractChannel, RNG: CryptoRng + Rng> Fancy for Garbler<C3, RNG> {
    type Item = Wire;
    type Error = TwopacError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.garbler.constant(x, q).map_err(Self::Error::from)
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
        self.garbler.output(x).map_err(Self::Error::from)
    }
}

impl<C3: AbstractChannel, RNG: CryptoRng + Rng, > FancyReveal for Garbler<C3, RNG> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.garbler.reveal(x).map_err(Self::Error::from)
    }
}

impl<C3, RNG> SemiHonest for Garbler<C3, RNG> {}
impl<C3, RNG> Malicious for Garbler<C3, RNG> {}
