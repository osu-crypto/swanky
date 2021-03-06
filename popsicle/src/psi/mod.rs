// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod kmprt;
#[cfg(feature = "psty")]
pub mod psty;
pub mod psz;

/// Private set intersection sender.
pub type Sender = psz::Sender;
/// Private set intersection receiver.
pub type Receiver = psz::Receiver;

#[cfg(feature = "psty")]
/// Extended private set intersection sender.
pub type ExtendedSender = psty::Sender;
#[cfg(feature = "psty")]
/// Extended private set intersection receiver.
pub type ExtendedReceiver = psty::Receiver;

/// Multi-party private set intersection sender.
pub type MultiPartySender = kmprt::Sender;
/// Multi-party private set intersection receiver.
pub type MultiPartyReceiver = kmprt::Receiver;
