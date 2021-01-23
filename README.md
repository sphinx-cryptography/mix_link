
# mix_link
[![](https://travis-ci.org/sphinx-cryptography/mix_link.png?branch=master)](https://www.travis-ci.org/sphinx-cryptography/mix_link) [![](https://img.shields.io/crates/v/mix_link.svg)](https://crates.io/crates/mix_link) [![](https://docs.rs/mix_link/badge.svg)](https://docs.rs/mix_link/)


This crate provides a Noise Protocol Framework based cryptographic
link layer wire protocol for constructing mix networks.


# warning

This code has not been formally audited. Use it at your own risk!


# details

This wire protocol is designed to construct mix networks.
You can read the design specification document here:

* https://github.com/katzenpost/docs/blob/master/specs/wire-protocol.rst

However note that I've change the prologue value (our protocol version number) to 1
instead of 0 to differentiate it from the older version which used NewHope Simple.
We now use the newer KEM, Kyber.

This cryptographic link layer protocol uses ``Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2b``.
You can read about the XX handshake pattern here in the Noise Protocol specification document:

* http://noiseprotocol.org/noise.html

However you'll also want to understand our hybrid forward secrecy protocol modification
using the Kyber post-quantum key encapsulation mechanism. Please see "KEM-based Hybrid Forward Secrecy for Noise":

* https://github.com/noiseprotocol/noise_hfs_spec/blob/master/output/noise_hfs.pdf


# Usage

To import `mix_link`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
mix_link = "^0.1.0"
```
Then import the crate as:
```rust,no_run
extern crate mix_link;
```


# acknowledgments

Thanks to Yawning Angel for the design of this wire protocol.
Thanks to Daan Sprenkels for implementing Kyber1024 HFS for Snow.


# license

GNU AFFERO GENERAL PUBLIC LICENSE

