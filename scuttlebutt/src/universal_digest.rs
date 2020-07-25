// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use digest::{FixedOutput, Input, Reset};
use universal_hash::{generic_array::{GenericArray, typenum::marker_traits::Unsigned}, UniversalHash};

/// Implementation of subtraits of `Digest` trait based on a universal hash function. Does not
/// implement `Digest` itself because it is insecure to construct a universal hash without a key.
#[derive(Clone)]
pub struct UniversalDigest<H: UniversalHash> {
    hash: H,
    buf_size: usize,
    buf: GenericArray<u8, H::BlockSize>,
}

impl<H: UniversalHash> UniversalDigest<H> {
    /// Create a `UniversalDigest` with the given `key`, which should be uniformly random.
    pub fn new(key: &GenericArray<u8, H::KeySize>) -> Self {
        Self::from(H::new(key))
    }
}

impl<H: UniversalHash> From<H> for UniversalDigest<H> {
    fn from(hash: H) -> Self {
        UniversalDigest { hash, buf_size: 0, buf: Default::default() }
    }
}

impl<H: UniversalHash> Input for UniversalDigest<H> {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        let block_size = H::BlockSize::to_usize();
        let mut data = data.as_ref();

        let unfilled_buf = &mut self.buf[self.buf_size..];
        if data.len() >= unfilled_buf.len() {
            if self.buf_size > 0 {
                let (start, data_) = data.split_at(unfilled_buf.len());
                data = data_;

                unfilled_buf.copy_from_slice(start);
                self.hash.update_block(GenericArray::from_slice(&self.buf));
            }

            let mut blocks = data.chunks_exact(block_size);
            for block in &mut blocks {
                self.hash.update_block(GenericArray::from_slice(block));
            }

            let rem = blocks.remainder();
            self.buf_size = rem.len();
            self.buf[..self.buf_size].copy_from_slice(rem);
        } else {
            unfilled_buf[..data.len()].copy_from_slice(data);
            self.buf_size += data.len();
        }
    }
}

impl<H: UniversalHash> Reset for UniversalDigest<H> {
    fn reset(&mut self) {
        self.buf_size = 0;
        self.hash.reset();
    }
}

impl<H: UniversalHash> FixedOutput for UniversalDigest<H> {
    type OutputSize = H::BlockSize;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        // Padding
        self.buf[self.buf_size] = 1;
        for x in &mut self.buf[self.buf_size+1..] { *x = 0 }
        self.hash.update_block(GenericArray::from_slice(&self.buf));

        self.hash.result().into_bytes()
    }
}
