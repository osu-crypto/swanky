// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{errors::{TwopacError, EvaluatorError}, util::tweak2, Fancy, FancyInput, FancyReveal, HasModulus, Garbler as Gb, threepac::malicious::PartyId, Wire};
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest, Malicious};

/// Semi-honest garbler.
pub struct Garbler<C3, RNG> {
    garbler: Gb<C3, RNG>,
    party: PartyId,
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
    pub fn new<C12: AbstractChannel>(party: PartyId, channel_p1_p2: &mut C12, channel_p3: C3, mut rng: RNG) -> Result<Self, TwopacError> {
        assert!(party != PartyId::Evaluator);

        let seed: Block;
        if party == PartyId::Garbler1 {
            seed = rng.gen();
            channel_p1_p2.write_block(&seed)?;
            channel_p1_p2.flush()?;
        } else {
            seed = channel_p1_p2.read_block()?;
        }

        let garbler = Gb::new(channel_p3, RNG::from_seed(seed));

        Ok(Garbler {
            garbler,
            party,
        })
    }

    pub fn get_channel(&mut self) -> &mut C3 {
        self.garbler.get_channel()
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
    type PartyId = PartyId;

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

    fn receive_many(&mut self, from: PartyId, qs: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        assert!(from != self.party);

        if from == PartyId::Evaluator {
            let shares = qs.iter().map(|_q| {
                self.garbler.get_channel().read_u16().map_err(Self::Error::from)
            }).collect::<Result<Vec<u16>, TwopacError>>()?;

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
                .map(|(w1, w2)| {
                    self.garbler.sub(w2, w1).map_err(Self::Error::from)
                })
                .collect::<Result<Vec<Wire>, TwopacError>>()?;
            Ok(wires)
        } else {
            let wires = qs.iter().map(|q| {
                let zero = self.garbler.create_wire(*q);
                let delta = self.garbler.delta(*q);

                // Commit to all wire labels. Order by color to avoid leaking which label has which value.
                let mut label = zero.minus(&delta.cmul(zero.color()));
                for i in 0..*q {
                    self.get_channel().write_block(&label.hash(tweak2(i as u64, 2)))?;
                    label = label.plus_mov(&delta);
                }
                Ok(zero)
            }).collect::<Result<Vec<Wire>, TwopacError>>()?;
            self.get_channel().flush()?;
            Ok(wires)
        }
    }
}

impl<C3: AbstractChannel, RNG: CryptoRng + Rng> Fancy for Garbler<C3, RNG> {
    type Item = Wire;
    type Error = TwopacError;

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
        self.garbler.output(x).map_err(Self::Error::from)
    }
}

impl<C3: AbstractChannel, RNG: CryptoRng + Rng, > FancyReveal for Garbler<C3, RNG> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        let q = x.modulus();

        self.output(x).map_err(Self::Error::from)?;
        self.get_channel().flush()?;
        let eval_wire = Wire::from_block(self.get_channel().read_block()?, x.modulus());
        let output = ((q as u32 + eval_wire.color() as u32 - x.color() as u32) % q as u32) as u16;

        // Check that the wire label is correct
        if self.garbler.delta(q).cmul_mov(output).plus_mov(x) != eval_wire {
            // TODO: Better errors
            return Err(TwopacError::EvaluatorError(EvaluatorError::DecodingFailed));
        }

        Ok(output)
    }
}

impl<C3, RNG> SemiHonest for Garbler<C3, RNG> {}
impl<C3, RNG> Malicious for Garbler<C3, RNG> {}
