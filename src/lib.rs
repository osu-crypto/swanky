// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `twopac` implements (semi-honest) garbled-circuit-based two-party secure
//! computation in rust, using `ocelot` for oblivious transfer and
//! `fancy-garbling` for garbled circuits.
//!
//! **THIS IS VERY MUCH RESEARCH CODE!** (for now)

#![cfg_attr(feature = "nightly", feature(test))]

mod comm;
mod errors;
mod evaluator;
mod garbler;

pub use errors::Error;
pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::dummy::Dummy;
    use fancy_garbling::util::RngExt;
    use fancy_garbling::{BundleGadgets, Fancy, HasModulus};
    use ocelot::*;
    use scuttlebutt::AesRng;
    use scuttlebutt::Block;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    type Reader = BufReader<UnixStream>;
    type Writer = BufWriter<UnixStream>;

    fn c1<F: Fancy<Item = W>, W: HasModulus + Clone>(f: &mut F) -> Result<(), F::Error> {
        let a = f.garbler_input(3, None)?;
        let b = f.evaluator_input(3)?;
        let c = f.add(&a, &b)?;
        f.output(&c)?;
        Ok(())
    }

    fn test_c1<
        OTSender: ObliviousTransferSender<Msg = Block>,
        OTReceiver: ObliviousTransferReceiver<Msg = Block>,
    >(
        a: u16,
        b: u16,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut gb =
                Garbler::<Reader, Writer, AesRng, OTSender>::new(reader, writer, &[a], rng)
                    .unwrap();
            c1(&mut gb).unwrap();
        });
        let rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut ev =
            Evaluator::<Reader, Writer, AesRng, OTReceiver>::new(reader, writer, &[b], rng)
                .unwrap();
        c1(&mut ev).unwrap();
        let output = ev.decode_output();
        assert_eq!(vec![(a + b) % 3], output);
    }

    type ChouOrlandiSender = chou_orlandi::ChouOrlandiOTSender;
    type ChouOrlandiReceiver = chou_orlandi::ChouOrlandiOTReceiver;

    #[test]
    fn test_simple_circuits() {
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(0, 0);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(1, 0);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(2, 0);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(0, 1);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(0, 2);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(1, 1);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(2, 1);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(1, 2);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(2, 2);
    }

    fn relu<F, W>(b: &F, q: u128, n: usize)
    where
        W: Clone + HasModulus + Send + Sync + std::fmt::Debug,
        F: Fancy<Item = W> + Send + Sync,
    {
        let mut zs = Vec::with_capacity(n);
        for _ in 0..n {
            let c = b.constant_bundle_crt(1, q).unwrap();
            let x = b.garbler_input_bundle_crt(q, None).unwrap();
            let x = b.mul_bundles(&x, &c).unwrap();
            let z = b.relu(&x, "100%", None).unwrap();
            zs.push(z);
        }
        b.output_bundles(&zs).unwrap();
    }

    #[test]
    fn test_complex_circuit() {
        let mut rng = rand::thread_rng();
        let n = 10;
        let q = fancy_garbling::util::modulus_with_width(10);
        let input = (0..n)
            .map(|_| fancy_garbling::util::crt_factor(rng.gen_u128() % q, q))
            .flatten()
            .collect::<Vec<u16>>();
        // Run dummy version.
        let dummy = Dummy::new(&input.clone(), &[]);
        relu(&dummy, q, n);
        let target = dummy.get_output();
        // Run 2PC version.
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let gb = Garbler::<Reader, Writer, AesRng, ChouOrlandiSender>::new(
                reader, writer, &input, rng,
            )
            .unwrap();
            relu(&gb, q, n);
        });
        let rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let ev =
            Evaluator::<Reader, Writer, AesRng, ChouOrlandiReceiver>::new(reader, writer, &[], rng)
                .unwrap();
        relu(&ev, q, n);
        let result = ev.decode_output();
        assert_eq!(target, result);
    }
}
