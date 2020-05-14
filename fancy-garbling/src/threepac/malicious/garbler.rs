// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{errors::TwopacError, Fancy, FancyInput, FancyReveal, Garbler as Gb, Wire};
use ocelot::ot::Sender as OtSender;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest, Malicious};

/// Semi-honest garbler.
pub struct Garbler<C12, C3, RNG, OT> {
    channel_p1_p2: C12,
    garbler: Gb<C3, RNG>,
    ot: OT,
    rng: RNG,
    is_p2: bool,
}

impl<C12, C3, OT, RNG> std::ops::Deref for Garbler<C12, C3, RNG, OT> {
    type Target = Gb<C3, RNG>;
    fn deref(&self) -> &Self::Target {
        &self.garbler
    }
}

impl<C12, C3, OT, RNG> std::ops::DerefMut for Garbler<C12, C3, RNG, OT> {
    fn deref_mut(&mut self) -> &mut Gb<C3, RNG> {
        &mut self.garbler
    }
}

impl<
        C12: AbstractChannel,
        C3: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
        OT: OtSender<Msg = Block>,
    > Garbler<C12, C3, RNG, OT>
{
    /// Make a new `Garbler`.
    pub fn new(is_p2: bool, mut channel_p1_p2: C12, mut channel_p3: C3, mut rng: RNG) -> Result<Self, TwopacError> {
        let ot = OT::init(&mut channel_p3, &mut rng)?;
        let garbler = Gb::new(channel_p3, RNG::from_seed(rng.gen()));
        Ok(Garbler {
            channel_p1_p2,
            garbler,
            ot,
            rng,
            is_p2,
        })
    }

    // TODO: get_channel

    fn _evaluator_input(&mut self, delta: &Wire, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let len = f32::from(q).log(2.0).ceil() as u16;
        let mut wire = Wire::zero(q);
        let inputs = (0..len)
            .map(|i| {
                let zero = Wire::rand(&mut self.rng, q);
                let one = zero.plus(&delta);
                wire = wire.plus(&zero.cmul(1 << i));
                (zero.as_block(), one.as_block())
            })
            .collect::<Vec<(Block, Block)>>();
        (wire, inputs)
    }
}

impl<
        C12: AbstractChannel,
        C3: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
        OT: OtSender<Msg = Block>,
    > FancyInput for Garbler<C12, C3, RNG, OT>
{
    type Item = Wire;
    type Error = TwopacError;

    fn encode(&mut self, val: u16, modulus: u16) -> Result<Wire, TwopacError> {
        let (mine, theirs) = self.garbler.encode_wire(val, modulus);
        self.garbler.send_wire(&theirs)?;
        self.get_channel().flush()?;
        Ok(mine)
    }

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
        self.get_channel().flush()?;
        ws
    }

    fn receive_many(&mut self, qs: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let n = qs.len();
        let lens = qs.iter().map(|q| f32::from(*q).log(2.0).ceil() as usize);
        let mut wires = Vec::with_capacity(n);
        let mut inputs = Vec::with_capacity(lens.sum());

        for q in qs.iter() {
            let delta = self.garbler.delta(*q);
            let (wire, input) = self._evaluator_input(&delta, *q);
            wires.push(wire);
            for i in input.into_iter() {
                inputs.push(i);
            }
        }
        self.ot.send(self.garbler.get_channel(), &inputs, &mut self.rng)?;
        Ok(wires)
    }
}

impl<C12: AbstractChannel, C3: AbstractChannel, RNG: CryptoRng + Rng, OT> Fancy for Garbler<C12, C3, RNG, OT> {
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

impl<C12: AbstractChannel, C3: AbstractChannel, RNG: CryptoRng + Rng, OT> FancyReveal for Garbler<C12, C3, RNG, OT> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.garbler.reveal(x).map_err(Self::Error::from)
    }
}

impl<C12, C3, RNG, OT> SemiHonest for Garbler<C12, C3, RNG, OT> {}
impl<C12, C3, RNG, OT> Malicious for Garbler<C12, C3, RNG, OT> {}
