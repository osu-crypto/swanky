// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{AbstractChannel};
use std::{
    io::{Read, Result, Write},
};

/// A channel for tracking the number of bits read/written.
pub struct TrackChannel<C> {
    channel: C,
    nbits_read: usize,
    nbits_written: usize,
}

impl<C: AbstractChannel> TrackChannel<C> {
    /// Make a new `TrackChannel` from a `reader` and a `writer`.
    pub fn new(channel: C) -> Self {
        TrackChannel {
            channel,
            nbits_read: 0,
            nbits_written: 0,
        }
    }

    /// Clear the number of bits read/written.
    pub fn clear(&mut self) {
        self.nbits_read = 0;
        self.nbits_written = 0;
    }

    /// Return the number of kilobits written to the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.nbits_written as f64 / 1000.0
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.nbits_read as f64 / 1000.0
    }

    /// Return the total amount of communication on the channel.
    pub fn total_kilobits(&self) -> f64 {
        (self.nbits_written + self.nbits_read) as f64 / 1000.0
    }

    /// Return the number of kilobytes written to the channel.
    pub fn kilobytes_written(&self) -> f64 {
        self.nbits_written as f64 / 8192.0
    }

    /// Return the number of kilobytes read from the channel.
    pub fn kilobytes_read(&self) -> f64 {
        self.nbits_read as f64 / 8192.0
    }

    /// Return the total amount of communication on the channel as kilobytes.
    pub fn total_kilobytes(&self) -> f64 {
        self.kilobytes_written() + self.kilobytes_read()
    }
}

impl<C: AbstractChannel> Read for TrackChannel<C> {
    fn read(&mut self, mut bytes: &mut [u8]) -> Result<usize> {
        let bytes_read = self.channel.read(&mut bytes)?;
        self.nbits_read += bytes_read * 8;
        Ok(bytes_read)
    }
}

impl<C: AbstractChannel> Write for TrackChannel<C> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        let bytes_written = self.channel.write(bytes)?;
        self.nbits_written += bytes_written * 8;
        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        self.channel.flush()
    }
}
