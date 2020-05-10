// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{AbstractChannel};
use sha2::{Digest, Sha256};
use std::io::{Read, Result, Write};

/// An instantiation of the `AbstractChannel` trait which computes a running
/// hash of all bytes read from and written to the channel.
pub struct HashChannel<C> {
    channel: C,
    hash: Sha256,
}

impl<C: AbstractChannel> HashChannel<C> {
    /// Make a new `HashChannel` from a `reader` and a `writer`.
    pub fn new(channel: C) -> Self {
        let hash = Sha256::new();
        Self { channel, hash }
    }

    /// Consume the channel and output the hash of all the communication.
    pub fn finish(self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.hash.result());
        h
    }
}

impl<C: AbstractChannel> Read for HashChannel<C> {
    #[inline]
    fn read(&mut self, mut bytes: &mut [u8]) -> Result<usize> {
        let bytes_read = self.channel.read(&mut bytes)?;
        self.hash.input(&bytes[..bytes_read]);
        Ok(bytes_read)
    }
}

impl<C: AbstractChannel> Write for HashChannel<C> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        let bytes_written = self.channel.write(bytes)?;
        self.hash.input(&bytes[..bytes_written]);
        Ok(bytes_written)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.channel.flush()
    }
}
