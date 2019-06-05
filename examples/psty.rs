// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection (PSTY) benchmarks using `criterion`.

use popsicle::psty::{Receiver, Sender};
use scuttlebutt::{AesRng, TrackChannel};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::SystemTime;

const NBYTES: usize = 15;
const SET_SIZE: usize = 1 << 12;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(NBYTES)).collect()
}

fn psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);

        let start = SystemTime::now();
        let mut sender = Sender::init(&mut channel, &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        sender.send(&mut channel, &inputs1, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            SET_SIZE,
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender communication (read): {:.2} Mb",
            channel.read_kilobits() / 1000.0
        );
        println!(
            "Sender communication (write): {:.2} Mb",
            channel.write_kilobits() / 1000.0
        );
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = TrackChannel::new(reader, writer);

    let start = SystemTime::now();
    let mut receiver = Receiver::init(&mut channel, &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = receiver.receive(&mut channel, &inputs2, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        SET_SIZE,
        start.elapsed().unwrap().as_millis()
    );
    let _ = handle.join().unwrap();
    println!(
        "Receiver communication (read): {:.2} Mb",
        channel.read_kilobits() / 1000.0
    );
    println!(
        "Receiver communication (write): {:.2} Mb",
        channel.write_kilobits() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    let rs = rand_vec_vec(SET_SIZE);
    psty(rs.clone(), rs.clone());
}
