// -*- mode: rust; -*-
//
// This file is part of threepac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of malicious three-party computation.

pub mod evaluator;
pub mod garbler;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum PartyId {
    Garbler1,
    Garbler2,
    Evaluator,
}

#[cfg(test)]
mod tests {
    use evaluator::Evaluator;
    use garbler::Garbler;
    use super::*;
    use crate::{
        circuit::Circuit,
        dummy::Dummy,
        util::RngExt,
        CrtBundle,
        CrtGadgets,
        Fancy,
        FancyReveal,
        FancyInput,
    };
    use itertools::Itertools;
    use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

    fn addition<F: Fancy + FancyReveal>(f: &mut F, a: &F::Item, b: &F::Item) -> Result<u16, F::Error> {
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
                        let rng = AesRng::new();
                        let mut gb =
                            Garbler::<UnixChannel, AesRng>::new(PartyId::Garbler1, &mut p1top2, p1top3, rng)
                                .unwrap();
                        let g1 = gb.encode(a, 3).unwrap();
                        let g2 = gb.receive(PartyId::Garbler2, 3).unwrap();
                        let ys = gb.receive(PartyId::Evaluator, 3).unwrap();

                        let inter_wire = gb.add(&g1, &g2).unwrap();
                        addition(&mut gb, &inter_wire, &ys).unwrap()
                    });
                    let handle2 = std::thread::spawn(move || {
                        let rng = AesRng::new();
                        let mut gb =
                            Garbler::<UnixChannel, AesRng>::new(PartyId::Garbler2, &mut p2top1, p2top3, rng)
                                .unwrap();
                        let g1 = gb.receive(PartyId::Garbler1, 3).unwrap();
                        let g2 = gb.encode(b, 3).unwrap();
                        let ys = gb.receive(PartyId::Evaluator, 3).unwrap();

                        let inter_wire = gb.add(&g1, &g2).unwrap();
                        addition(&mut gb, &inter_wire, &ys).unwrap()
                    });
                    let rng = AesRng::new();
                    let mut gb =
                        Evaluator::<UnixChannel, UnixChannel, AesRng>::new(p3top1, p3top2, rng)
                            .unwrap();
                    let g1 = gb.receive(PartyId::Garbler1, 3).unwrap();
                    let g2 = gb.receive(PartyId::Garbler2, 3).unwrap();
                    let ys = gb.encode(c, 3).unwrap();

                    let inter_wire = gb.add(&g1, &g2).unwrap();
                    let output_ev = addition(&mut gb, &inter_wire, &ys).unwrap();

                    let output_g1 = handle1.join().unwrap();
                    let output_g2 = handle2.join().unwrap();

                    assert_eq!((a + b + c) % 3, output_ev);
                    assert_eq!(output_ev, output_g1);
                    assert_eq!(output_ev, output_g2);
                }
            }
        }
    }

    fn relu<F: Fancy>(b: &mut F, xs: &[CrtBundle<F::Item>]) -> Option<Vec<u128>> {
        let mut outputs = Vec::new();
        for x in xs.iter() {
            let q = x.composite_modulus();
            let c = b.crt_constant_bundle(1, q).unwrap();
            let y = b.crt_mul(&x, &c).unwrap();
            let z = b.crt_relu(&y, "100%", None).unwrap();
            outputs.push(b.crt_output(&z).unwrap());
        }
        outputs.into_iter().collect()
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
        std::thread::spawn(move || {
            let rng = AesRng::new();
            let mut gb =
                Garbler::<UnixChannel, AesRng>::new(PartyId::Garbler1, &mut p1top2, p1top3, rng)
                    .unwrap();
            let g1 = gb.crt_encode_many(&input, q).unwrap();
            relu(&mut gb, &g1);
        });

        std::thread::spawn(move || {
            let rng = AesRng::new();
            let mut gb =
                Garbler::<UnixChannel, AesRng>::new(PartyId::Garbler2, &mut p2top1, p2top3, rng)
                    .unwrap();
            let g1 = gb.crt_receive_many(PartyId::Garbler1, n, q).unwrap();
            relu(&mut gb, &g1);
        });

        let rng = AesRng::new();
        let mut ev =
            Evaluator::<UnixChannel, UnixChannel, AesRng>::new(p3top1, p3top2, rng)
                .unwrap();
        let g1 = ev.crt_receive_many(PartyId::Garbler1, n, q).unwrap();
        let result = relu(&mut ev, &g1).unwrap();
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
            let rng = AesRng::new();
            let mut gb =
                Garbler::<UnixChannel, AesRng>::new(PartyId::Garbler1, &mut p1top2, p1top3, rng)
                    .unwrap();
            let mut g1 = gb.encode_many(&vec![0_u16; 64], &vec![2; 64]).unwrap();
            let mut g2 = gb.receive_many(PartyId::Garbler2, &vec![2; 64]).unwrap();
            let ys = gb.receive_many(PartyId::Evaluator, &vec![2; 128]).unwrap();

            g1.append(&mut g2);
            circ_1.eval(&mut gb, &g1, &ys).unwrap();
        });

        let handle2 = std::thread::spawn(move || {
            let rng = AesRng::new();
            let mut gb =
                Garbler::<UnixChannel, AesRng>::new(PartyId::Garbler2, &mut p2top1, p2top3, rng)
                    .unwrap();
            let mut g1 = gb.receive_many(PartyId::Garbler1, &vec![2; 64]).unwrap();
            let mut g2 = gb.encode_many(&vec![0_u16; 64], &vec![2; 64]).unwrap();
            let ys = gb.receive_many(PartyId::Evaluator, &vec![2; 128]).unwrap();

            g1.append(&mut g2);
            circ_2.eval(&mut gb, &g1, &ys).unwrap();
        });

        let rng = AesRng::new();
        let mut ev =
            Evaluator::<UnixChannel, UnixChannel, AesRng>::new(p3top1, p3top2, rng)
                .unwrap();
        let mut g1 = ev.receive_many(PartyId::Garbler1, &vec![2; 64]).unwrap();
        let mut g2 = ev.receive_many(PartyId::Garbler2, &vec![2; 64]).unwrap();
        let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();

        g1.append(&mut g2);
        circ.eval(&mut ev, &g1, &ys).unwrap();
        handle1.join().unwrap();
        handle2.join().unwrap();
    }
}
