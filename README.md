# The `scuttlebutt` multi-party computation utilities toolkit [![](https://travis-ci.org/GaloisInc/scuttlebutt.svg?branch=master)](https://travis-ci.org/GaloisInc/scuttlebutt)
Or: "Where rust MPC libraries come to drink"

The `scuttlebutt` library provides a bunch of core primitives for building
multi-party computation (MPC) related protocols, such as garbled circuits or
oblivious transfer. In particular, `scuttlebutt` provides the following:

* `AbstractChannel`, which provides a trait for a read/write communication
  channel. The library also includes two implementations of said trait:
  `Channel` for your basic channel needs, and `TrackChannel` for additionally
  recording the number of bytes read/written to the channel.
* `Aes128` and `Aes256`, which provide AES encryption capabilities using AES-NI.
* `AesHash`, which provides correlation-robust hash functions based on
  fixed-key AES (cf. <https://eprint.iacr.org/2019/074>).
* `AesRng`, which provides a random number generator based on fixed-key AES.
* `Block`, which wraps a 128-bit value and provides methods operating on that value.
* `Block512`, which wraps a 512-bit value and provides methods operating on that value.
* A `cointoss` module, which implements a simple random-oracle-based coin-tossing protocol.
* A `commitment` module, which provides a `Commitment` trait and an
  implementation `ShaCommitment` using SHA-256.
* A `utils` module, which contains useful utility functions.

**`scuttlebutt` should be considered unstable and under active development until
version 1.0 is released**

# Building

Use `cargo build` to build, `cargo test` to run the test suite, and `cargo
bench` to benchmark the various protocols.

`scuttlebutt` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.
* `curve25519-dalek`: Enable functions that use `curve25519-dalek`.
* `serde`: Enable `serde` support.
* `unstable`: Enable unstable features.

# License

MIT License

# Authors

- Alex J. Malozemoff <amaloz@galois.com>

# Acknowledgments

This material is based upon work supported by the ARO and DARPA under Contract
No. W911NF-15-C-0227.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO and DARPA.

Copyright © 2019 Galois, Inc.
