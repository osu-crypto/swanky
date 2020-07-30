// -*- mode: rust; -*-
//
// This file is part of threepac.
// See LICENSE for licensing information.

//! # Three-party honest-majority multi-party computation with garbled circuits
//!
//! Implementation of honest-majority three-party malicious secure computation from
//! ["Fast and Secure Three-party Computation: The Garbled Circuit Approach"](https://eprint.iacr.org/2015/931.pdf).
//! Roughly speaking, the idea is to protect against a malicious garbler by having two garblers,
//! where the evaluator checks that they both send the same data. As an optimization to save
//! bandwidth, we instead have the garblers take turns either sending the garbled circuit or sending
//! a hash of it. The evaluator secret shares its inputs to the two garblers, thus avoiding the need
//! for oblivious transfer.
//!
//! ## Usage
//!
//! There are a few parameters to select. The protocol requires a random number generator and a
//! [`UniversalHash`](universal_hash::UniversalHash). In the example below, we will use
//! [`AesRng`](scuttlebutt::AesRng) and
//! [`Poly1305`](https://docs.rs/poly1305/0.6.0/poly1305/struct.Poly1305.html).
//! We also need to provide channels to communicate between the parties, and to select how many bytes are sent by one garbler before switching to the other.
//!
//! ```ignore
//! const HASH_CHUNK_SIZE: usize = 0x1000;
//! let mut ev = Evaluator::<UnixChannel, UnixChannel, AesRng, Poly1305>::new(
//!     ev_channel_gb_1,
//!     ev_channel_gb_2,
//!     AesRng::new(),
//!     HASH_CHUNK_SIZE,
//! );
//! ```
//!
//! Inputs to the garbled circuit are provided through [`encode`](crate::FancyInput::encode), and
//! inputs from other parties are indicated with [`receive`](crate::FancyInput::receive).
//!
//! ```ignore
//! let a = ev.encode(input_a, 2)?;            // Input the modulo 2 value input_a.
//! let b = ev.receive(PartyId::Garbler1, 2)?; // Garbler 1 inputs a modulo 2 value.
//! let c = ev.receive(PartyId::Garbler2, 2)?;
//! ```
//!
//! Each party will run through all of the gates in the circuit, calling a function from
//! [`Fancy`](crate::Fancy) for each gate. Circuits can also be loaded from a file with
//! [`Circuit::parse()`](crate::circuit::Circuit::parse), and executed with
//! [`eval()`](crate::circuit::Circuit::eval). Next, the result is revealed to all parties. Note
//! that [`FancyReveal::reveal()`](crate::FancyReveal::reveal()) is used for this, not
//! [`Fancy::output()`](crate::Fancy::output()) which only reveals the result to the evaluator.
//!
//! ```ignore
//! let t = ev.and(&a, &b)?;
//! let r = ev.and(&t, &c)?;
//! let result = ev.reveal(&r);
//! ```
//!
//! The different parties communicate over [`AbstractChannel`](scuttlebutt::AbstractChannel)s, and
//! we will use Unix domain sockets, with each party running in its own thread of the same machine.
//!
//! ```ignore
//! let (ev_channel_gb_1, gb_1_channel_ev) = unix_channel_pair();
//! let (ev_channel_gb_2, gb_2_channel_ev) = unix_channel_pair();
//! let (gb_1_channel_gb_2, gb_2_channel_gb_1) = unix_channel_pair();
//! ```
//!
//! The complete example follows.
//!
//! ```
//! # use poly1305::Poly1305;
//! # use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};
//! # use fancy_garbling::threepac::malicious::*;
//! # use evaluator::Evaluator;
//! # use garbler::Garbler;
//! # use fancy_garbling::{
//! #     Fancy,
//! #     FancyInput,
//! #     FancyReveal,
//! # };
//! # for input_a in 0..2 {
//! #     for input_b in 0..2 {
//! #         for input_c in 0..2 {
//! const HASH_CHUNK_SIZE: usize = 0x1000;
//!
//! let (ev_channel_gb_1, gb_1_channel_ev) = unix_channel_pair();
//! let (ev_channel_gb_2, gb_2_channel_ev) = unix_channel_pair();
//! let (mut gb_1_channel_gb_2, mut gb_2_channel_gb_1) = unix_channel_pair();
//!
//! let handle_ev = std::thread::spawn(move || {
//!     let mut ev = Evaluator::<UnixChannel, UnixChannel, AesRng, Poly1305>::new(
//!         ev_channel_gb_1,
//!         ev_channel_gb_2,
//!         AesRng::new(),
//!         HASH_CHUNK_SIZE,
//!     )?;
//!
//!     let a = ev.encode(input_a, 2)?;
//!     let b = ev.receive(PartyId::Garbler1, 2)?;
//!     let c = ev.receive(PartyId::Garbler2, 2)?;
//!
//!     let t = ev.and(&a, &b)?;
//!     let r = ev.and(&t, &c)?;
//!     ev.reveal(&r)
//! });
//!
//! let handle_gb_1 = std::thread::spawn(move || {
//!     let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
//!         PartyId::Garbler1,
//!         &mut gb_1_channel_gb_2,
//!         gb_1_channel_ev,
//!         &mut AesRng::new(),
//!         HASH_CHUNK_SIZE,
//!     )?;
//!
//!     let a = gb.receive(PartyId::Evaluator, 2)?;
//!     let b = gb.encode(input_b, 2)?;
//!     let c = gb.receive(PartyId::Garbler2, 2)?;
//!
//!     let t = gb.and(&a, &b)?;
//!     let r = gb.and(&t, &c)?;
//!     gb.reveal(&r)
//! });
//!
//! let handle_gb_2 = std::thread::spawn(move || {
//!     let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
//!         PartyId::Garbler2,
//!         &mut gb_2_channel_gb_1,
//!         gb_2_channel_ev,
//!         &mut AesRng::new(),
//!         HASH_CHUNK_SIZE,
//!     )?;
//!
//!     let a = gb.receive(PartyId::Evaluator, 2)?;
//!     let b = gb.receive(PartyId::Garbler1, 2)?;
//!     let c = gb.encode(input_c, 2)?;
//!
//!     let t = gb.and(&a, &b)?;
//!     let r = gb.and(&t, &c)?;
//!     gb.reveal(&r)
//! });
//!
//! let output_ev = handle_ev.join().unwrap().unwrap();
//! let output_gb_1 = handle_gb_1.join().unwrap().unwrap();
//! let output_gb_2 = handle_gb_2.join().unwrap().unwrap();
//!
//! assert_eq!(input_a & input_b & input_c, output_ev);
//! assert_eq!(output_ev, output_gb_1);
//! assert_eq!(output_ev, output_gb_2);
//! #         }
//! #     }
//! # }
//! ```
//!
//! ## Benchmarks
//! 
//! This module utilizes [`criterion`](https://docs.rs/criterion/0.3.3/criterion/) for benchmarking
//! purposes. It is possible to run this benchmark on your own machine using cargo:
//!
//! ```
//! $ cargo bench --bench malicious_3pc
//! ```
//!
//! Our benchmark uses unix channels to simulate communication between the parties.
//! We ran our benchmark with 10 samples and 100ms of warm up, evaluating AES, SHA-1, and SHA-256
//! as the benchmark cases.
//!
//! Following are the summarized results generated by a machine running on:
//! Intel Core i7-8550U CPU @ 1.80GHz and 16 GB of DDR4 RAM.
//!
//! ### AES Benchmark
//!
//! Evaluation of AES encryption between three parties
//!
//! |              |Lower Bound| Estimate  |Upper Bound|
//! |--------------|-----------|-----------|-----------|
//! | **Mean**     | 6.2240 ms | 6.2356 ms | 6.2525 ms |
//! | **Std. Dev.**| 3.6750 us | 25.533 us | 38.340 us |
//!
//!
//! ### SHA-1 Benchmark
//!
//! Evaluation of SHA-1 hash between three parties
//!
//! |              |Lower Bound| Estimate  |Upper Bound|
//! |--------------|-----------|-----------|-----------|
//! | **Mean**     | 30.695 ms | 30.972 ms | 31.304 ms |
//! | **Std. Dev.**| 230.88 us | 526.50 us | 720.63 us |
//!
//!
//! ### SHA-256 Benchmark
//!
//! Evaluation of SHA-256 hash between three parties
//!
//! |              |Lower Bound| Estimate  |Upper Bound|
//! |--------------|-----------|-----------|-----------|
//! | **Mean**     | 55.387 ms | 55.509 ms | 55.669 ms |
//! | **Std. Dev.**| 45.758 us | 244.34 us | 344.74 us |
//! 
//!
 
 




//#![cfg_attr(feature = "nightly", doc(include = "README.md"))]

#![allow(missing_docs)]

pub mod evaluator;
pub mod garbler;

/// Identify a participant in the garbled circuit protocol. There are two garblers and one
/// evaluator.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum PartyId {
    Garbler1,
    Garbler2,
    Evaluator,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Circuit,
        dummy::Dummy,
        util::RngExt,
        CrtBundle,
        CrtGadgets,
        Fancy,
        FancyInput,
        FancyReveal,
    };
    use evaluator::Evaluator;
    use garbler::Garbler;
    use itertools::Itertools;
    use poly1305::Poly1305;
    use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

    const HASH_CHUNK_SIZE: usize = 0x1000;

    fn addition<F: Fancy + FancyReveal>(
        f: &mut F,
        a: &F::Item,
        b: &F::Item,
    ) -> Result<u16, F::Error> {
        let c = f.add(&a, &b)?;
        f.reveal(&c)
    }

    #[test]
    fn test_addition_circuit() {
        for a in 0..2 {
            for b in 0..2 {
                for c in 0..2 {
                    let (mut p1top2, mut p2top1) = unix_channel_pair();
                    let (p3top1, p1top3) = unix_channel_pair();
                    let (p3top2, p2top3) = unix_channel_pair();
                    let handle1 = std::thread::spawn(move || {
                        let mut rng = AesRng::new();
                        let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
                            PartyId::Garbler1,
                            &mut p1top2,
                            p1top3,
                            &mut rng,
                            HASH_CHUNK_SIZE,
                        )?;
                        let g1 = gb.encode(a, 3)?;
                        let g2 = gb.receive(PartyId::Garbler2, 3)?;
                        let ys = gb.receive(PartyId::Evaluator, 3)?;

                        let inter_wire = gb.add(&g1, &g2)?;
                        addition(&mut gb, &inter_wire, &ys)
                    });
                    let handle2 = std::thread::spawn(move || {
                        let mut rng = AesRng::new();
                        let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
                            PartyId::Garbler2,
                            &mut p2top1,
                            p2top3,
                            &mut rng,
                            HASH_CHUNK_SIZE,
                        )?;
                        let g1 = gb.receive(PartyId::Garbler1, 3)?;
                        let g2 = gb.encode(b, 3)?;
                        let ys = gb.receive(PartyId::Evaluator, 3)?;

                        let inter_wire = gb.add(&g1, &g2)?;
                        addition(&mut gb, &inter_wire, &ys)
                    });
                    let rng = AesRng::new();
                    let mut gb = Evaluator::<UnixChannel, UnixChannel, AesRng, Poly1305>::new(
                        p3top1,
                        p3top2,
                        rng,
                        HASH_CHUNK_SIZE,
                    )
                    .unwrap();
                    let g1 = gb.receive(PartyId::Garbler1, 3).unwrap();
                    let g2 = gb.receive(PartyId::Garbler2, 3).unwrap();
                    let ys = gb.encode(c, 3).unwrap();

                    let inter_wire = gb.add(&g1, &g2).unwrap();
                    let output_ev = addition(&mut gb, &inter_wire, &ys).unwrap();

                    let output_g1 = handle1.join().unwrap().unwrap();
                    let output_g2 = handle2.join().unwrap().unwrap();

                    assert_eq!((a + b + c) % 3, output_ev);
                    assert_eq!(output_ev, output_g1);
                    assert_eq!(output_ev, output_g2);
                }
            }
        }
    }

    fn relu<F: Fancy>(b: &mut F, xs: &[CrtBundle<F::Item>]) -> Result<Option<Vec<u128>>, F::Error> {
        let mut outputs = Vec::new();
        for x in xs.iter() {
            let q = x.composite_modulus();
            let c = b.crt_constant_bundle(1, q)?;
            let y = b.crt_mul(&x, &c)?;
            let z = b.crt_relu(&y, "100%", None)?;
            outputs.push(b.crt_output(&z)?);
        }
        Ok(outputs.into_iter().collect())
    }

    #[test]
    fn test_relu() {
        let mut rng = rand::thread_rng();
        let n = 10;
        let ps = crate::util::primes_with_width(10);
        let q = crate::util::product(&ps);
        let input = (0..n).map(|_| rng.gen_u128() % q).collect::<Vec<u128>>();

        // Run dummy version.
        let mut dummy = Dummy::new();
        let dummy_input = input
            .iter()
            .map(|x| dummy.crt_encode(*x, q).unwrap())
            .collect_vec();
        let target = relu(&mut dummy, &dummy_input).unwrap();

        // Run 3PC version.
        let (mut p1top2, mut p2top1) = unix_channel_pair();
        let (p3top1, p1top3) = unix_channel_pair();
        let (p3top2, p2top3) = unix_channel_pair();
        let handle1 = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
                PartyId::Garbler1,
                &mut p1top2,
                p1top3,
                &mut rng,
                HASH_CHUNK_SIZE,
            )?;
            let g1 = gb.crt_encode_many(&input, q)?;
            relu(&mut gb, &g1)
        });

        let handle2 = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
                PartyId::Garbler2,
                &mut p2top1,
                p2top3,
                &mut rng,
                HASH_CHUNK_SIZE,
            )?;
            let g1 = gb.crt_receive_many(PartyId::Garbler1, n, q)?;
            relu(&mut gb, &g1)
        });

        let rng = AesRng::new();
        let mut ev = Evaluator::<UnixChannel, UnixChannel, AesRng, Poly1305>::new(
            p3top1,
            p3top2,
            rng,
            HASH_CHUNK_SIZE,
        )
        .unwrap();
        let g1 = ev.crt_receive_many(PartyId::Garbler1, n, q).unwrap();
        let result = relu(&mut ev, &g1).unwrap();
        handle1.join().unwrap().unwrap();
        handle2.join().unwrap().unwrap();
        assert_eq!(target, result);
    }

    #[test]
    fn test_aes() {
        let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();

        circ.print_info().unwrap();
        let circ_1 = circ.clone();
        let circ_2 = circ.clone();

        let (mut p1top2, mut p2top1) = unix_channel_pair();
        let (p3top1, p1top3) = unix_channel_pair();
        let (p3top2, p2top3) = unix_channel_pair();

        let handle1 = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
                PartyId::Garbler1,
                &mut p1top2,
                p1top3,
                &mut rng,
                HASH_CHUNK_SIZE,
            )?;
            let mut g1 = gb.encode_many(&vec![0_u16; 64], &vec![2; 64])?;
            let mut g2 = gb.receive_many(PartyId::Garbler2, &vec![2; 64])?;
            let ys = gb.receive_many(PartyId::Evaluator, &vec![2; 128])?;

            g1.append(&mut g2);
            circ_1.eval(&mut gb, &g1, &ys)
        });

        let handle2 = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut gb = Garbler::<UnixChannel, AesRng, Poly1305>::new(
                PartyId::Garbler2,
                &mut p2top1,
                p2top3,
                &mut rng,
                HASH_CHUNK_SIZE,
            )?;
            let mut g1 = gb.receive_many(PartyId::Garbler1, &vec![2; 64])?;
            let mut g2 = gb.encode_many(&vec![0_u16; 64], &vec![2; 64])?;
            let ys = gb.receive_many(PartyId::Evaluator, &vec![2; 128])?;

            g1.append(&mut g2);
            circ_2.eval(&mut gb, &g1, &ys)
        });

        let rng = AesRng::new();
        let mut ev = Evaluator::<UnixChannel, UnixChannel, AesRng, Poly1305>::new(
            p3top1,
            p3top2,
            rng,
            HASH_CHUNK_SIZE,
        )
        .unwrap();
        let mut g1 = ev.receive_many(PartyId::Garbler1, &vec![2; 64]).unwrap();
        let mut g2 = ev.receive_many(PartyId::Garbler2, &vec![2; 64]).unwrap();
        let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();

        g1.append(&mut g2);
        circ.eval(&mut ev, &g1, &ys).unwrap();
        handle1.join().unwrap().unwrap();
        handle2.join().unwrap().unwrap();
    }
}
