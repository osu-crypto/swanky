// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Provides objects and functions for statically garbling and evaluating a
//! circuit without streaming.

use crate::{
    circuit::Circuit,
    errors::{EvaluatorError, GarblerError},
    fancy::HasModulus,
    garble::{Evaluator, Garbler},
    wire::Wire,
};
use itertools::Itertools;
use scuttlebutt::{AesRng, Channel};
use std::collections::HashMap;

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct GarbledCircuit {
    data: Vec<u8>,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled data
    pub fn new(data: Vec<u8>) -> Self {
        GarbledCircuit { data }
    }

    /// The number of bytes in the garbled circuit.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &self,
        c: &Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<u16>, EvaluatorError> {
        let channel = Channel::new(&self.data[..], vec![]);
        let mut evaluator = Evaluator::new(channel);
        let outputs = c.eval(&mut evaluator, garbler_inputs, evaluator_inputs)?;
        Ok(outputs.expect("evaluator outputs always are Some(u16)"))
    }
}

/// Garble a circuit without streaming.
pub fn garble(c: &Circuit) -> Result<(Encoder, GarbledCircuit), GarblerError> {
    let mut garbled_data = vec![];
    let mut channel = Channel::new(
        &[] as &[u8],
        &mut garbled_data
    );

    let rng = AesRng::new();
    let en = {
        let mut garbler = Garbler::new(&mut channel, rng);

        // get input wires, ignoring encoded values
        let gb_inps = (0..c.num_garbler_inputs())
            .map(|i| {
                let q = c.garbler_input_mod(i);
                let (zero, _) = garbler.encode_wire(0, q);
                zero
            })
            .collect_vec();

        let ev_inps = (0..c.num_evaluator_inputs())
            .map(|i| {
                let q = c.evaluator_input_mod(i);
                let (zero, _) = garbler.encode_wire(0, q);
                zero
            })
            .collect_vec();

        c.eval(&mut garbler, &gb_inps, &ev_inps)?;

        Encoder::new(gb_inps, ev_inps, garbler.get_deltas())
    };

    let gc = GarbledCircuit::new(garbled_data);

    Ok((en, gc))
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically.
#[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct Encoder {
    garbler_inputs: Vec<Wire>,
    evaluator_inputs: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
}

impl Encoder {
    /// Make a new `Encoder` from lists of garbler and evaluator inputs,
    /// alongside a map of moduli-to-wire-offsets.
    pub fn new(
        garbler_inputs: Vec<Wire>,
        evaluator_inputs: Vec<Wire>,
        deltas: HashMap<u16, Wire>,
    ) -> Self {
        Encoder {
            garbler_inputs,
            evaluator_inputs,
            deltas,
        }
    }

    /// Output the number of garbler inputs.
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_inputs.len()
    }

    /// Output the number of evaluator inputs.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_inputs.len()
    }

    /// Encode a single garbler input into its associated wire-label.
    pub fn encode_garbler_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.garbler_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    /// Encode a single evaluator input into its associated wire-label.
    pub fn encode_evaluator_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.evaluator_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    /// Encode a slice of garbler inputs into their associated wire-labels.
    pub fn encode_garbler_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.garbler_inputs.len());
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_garbler_input(x, id))
            .collect()
    }

    /// Encode a slice of evaluator inputs into their associated wire-labels.
    pub fn encode_evaluator_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.evaluator_inputs.len());
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_evaluator_input(x, id))
            .collect()
    }
}
