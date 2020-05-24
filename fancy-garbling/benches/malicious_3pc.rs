// -*- mode: rust; -*-
//
// This file is part of `twopac`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Benchmarks for malicious 3PC using `fancy-garbling`.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{
    circuit::Circuit,
    threepac::malicious::{evaluator::Evaluator, garbler::Garbler, PartyId},
    FancyInput,
};
use poly1305::Poly1305;
use scuttlebutt::{AesRng, Channel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

type Reader = BufReader<UnixStream>;
type Writer = BufWriter<UnixStream>;
type UnixChannel = Channel<Reader, Writer>;

const HASH_CHUNK_SIZE: usize = 0x1000;

fn circuit(fname: &str) -> Circuit {
    Circuit::parse(fname).unwrap()
}

pub fn unix_channel_pair() -> (UnixChannel, UnixChannel) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let sender = Channel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
    let receiver = Channel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
    (sender, receiver)
}

fn _bench_circuit(circ: &Circuit, gb1_inputs: Vec<u16>, gb2_inputs: Vec<u16>, ev_inputs: Vec<u16>) {

    let (mut p1top2, mut p2top1) = unix_channel_pair();
    let (p3top1, p1top3) = unix_channel_pair();
    let (p3top2, p2top3) = unix_channel_pair();

    let circ_1 = circ.clone();
    let circ_2 = circ.clone();

    let n_gb1_inputs = gb1_inputs.len();
    let n_gb2_inputs = gb2_inputs.len();
    let n_ev_inputs = ev_inputs.len();

    let handle1 = std::thread::spawn(move || {
        let rng = AesRng::new();
        let mut gb =
            Garbler::<UnixChannel, AesRng, Poly1305>::new(PartyId::Garbler1, &mut p1top2, p1top3, rng, HASH_CHUNK_SIZE)
            .unwrap();
        let mut xs1 = gb.encode_many(&gb1_inputs, &vec![2; n_gb1_inputs]).unwrap();
        let mut xs2 = gb.receive_many(PartyId::Garbler2, &vec![2; n_gb2_inputs]).unwrap();
        let ys = gb.receive_many(PartyId::Evaluator, &vec![2; n_ev_inputs]).unwrap();

        xs1.append(&mut xs2);
        circ_1.eval(&mut gb, &xs1, &ys).unwrap();
    });
    let handle2 = std::thread::spawn(move || {
        let rng = AesRng::new();
        let mut gb =
            Garbler::<UnixChannel, AesRng, Poly1305>::new(PartyId::Garbler2, &mut p2top1, p2top3, rng, HASH_CHUNK_SIZE)
            .unwrap();
        let mut xs1 = gb.receive_many(PartyId::Garbler1, &vec![2; n_gb1_inputs]).unwrap();
        let mut xs2 = gb.encode_many(&gb2_inputs, &vec![2; n_gb2_inputs]).unwrap();
        let ys = gb.receive_many(PartyId::Evaluator, &vec![2; n_ev_inputs]).unwrap();

        xs1.append(&mut xs2);
        circ_2.eval(&mut gb, &xs1, &ys).unwrap();
    });
    let rng = AesRng::new();
    let mut ev =
        Evaluator::<UnixChannel, UnixChannel, AesRng, Poly1305>::new(p3top1, p3top2, rng, HASH_CHUNK_SIZE)
            .unwrap();
    let mut g1 = ev.receive_many(PartyId::Garbler1, &vec![2; n_gb1_inputs]).unwrap();
    let mut g2 = ev.receive_many(PartyId::Garbler2, &vec![2; n_gb2_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();

    g1.append(&mut g2);
    circ.eval(&mut ev, &g1, &ys).unwrap();
    handle1.join().unwrap();
    handle2.join().unwrap();
}

fn bench_aes(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("threepac::malicious (AES)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 64], vec![1u16; 64], vec![0u16; 128]))
    });
}

fn bench_sha_1(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("threepac::malicious (SHA-1)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 256], vec![1u16; 256], vec![]))
    });
}

fn bench_sha_256(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("threepac::malicious-honest (SHA-256)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 256], vec![1u16; 256], vec![]))
    });
}

criterion_group! {
    name = malicious;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_aes, bench_sha_1, bench_sha_256
}

criterion_main!(malicious);
