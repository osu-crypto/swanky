// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{Channel, TrackChannel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

/// A Channel which uses UnixStreams.
pub type UnixChannel = Channel<BufReader<UnixStream>, BufWriter<UnixStream>>;

/// A TrackChannel which uses UnixStreams.
pub type TrackUnixChannel = TrackChannel<Channel<BufReader<UnixStream>, BufWriter<UnixStream>>>;

/// Convenience function to create a pair of UnixChannels for local tests in `swanky`.
pub fn unix_channel_pair() -> (UnixChannel, UnixChannel) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let sender = Channel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
    let receiver = Channel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
    (sender, receiver)
}

/// Convenience function to create a pair of TrackUnixChannels for local tests in `swanky`.
pub fn track_unix_channel_pair() -> (TrackUnixChannel, TrackUnixChannel) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let sender = TrackChannel::new(Channel::new(
        BufReader::new(tx.try_clone().unwrap()),
        BufWriter::new(tx),
    ));
    let receiver = TrackChannel::new(Channel::new(
        BufReader::new(rx.try_clone().unwrap()),
        BufWriter::new(rx),
    ));
    (sender, receiver)
}
