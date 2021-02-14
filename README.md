
# mix_link
[![](https://travis-ci.org/sphinx-cryptography/mix_link.png?branch=master)](https://www.travis-ci.org/sphinx-cryptography/mix_link) [![](https://img.shields.io/crates/v/mix_link.svg)](https://crates.io/crates/mix_link) [![](https://docs.rs/mix_link/badge.svg)](https://docs.rs/mix_link/)


This crate provides a post-quantum Noise Protocol Framework based
cryptographic wire protocol for constructing mix networks. The main
intention of this protocol is to interoperate with the Katzenpost wire
protocol. That is, this crate could be used in the composition of a
Rust client for the Katzenpost decryption mix network.

What is a mix network?
A mix network is a message oriented anonymous communication network
which in some ways has a much stronger threat model than Tor. Although
the use cases tend to be different because it is generally agreed that
mix networks are not good for browsing the web or video streaming.
This is because mix networks are usually medium to high latency.
However in the case of continuous time mixes such as the Stop and Go
mix, Loopix and Katzenpost, these designs make it possible to have
relatively low latency compared to say Pool mix strategy for example.
That having been said, the latency might approach "almost low latency"
but there will still be bandwidth limitations preventing such applications
requiring largish downloads. We therefore feel the need to suggest that
mix networks are probably best used as a transport for messaging systems
where the message sizes are relatively small and the sending of messages
are rather infrequent. Think "pond", as in agl's [pond](https://github.com/agl/pond).
Instead of whining about how agl completely abandoned pond and quite a few
ex-Tor developers completely abandoned working on anonymous communication
in general, why not instead make something new and better than previous designs
for the narrow use case of a pond-like messaging application?

# status

This implementation has been tested and is informally verified to interoperate
with the Katzenpost wire protocol written in the Go language. However this crate
is still a work-in-progress. Further improvements will be made soon.


# warning

This code has not been formally audited. Use it at your own risk!


# details

You can read the slightly out of date design specification document here:

* https://github.com/katzenpost/docs/blob/master/specs/wire-protocol.rst

There are two notable differences from this specification:
1. We use Kyber instead of New Hope Simple.
2. The prologue value is set to 2 (as in the byte value of 0x02) to
   differentiate it from older versions of the protocol.

The Golang implementation of this wire protocol can be found here:
https://github.com/katzenpost/core/tree/master/wire

This protocol uses a Noise protocol name of ``Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2b``
which means that a Hybrid Forward Secret Noise protocol modifier is used as described in the
latest version of the "KEM-based Hybrid Forward Secrecy for Noise" specification:

* https://github.com/noiseprotocol/noise_hfs_spec/blob/master/output/noise_hfs.pdf

We use Kyber (NIST round 3), a post quantum key encapsulation mechanism which you can read
about at their official website here:

* https://pq-crystals.org/kyber/

You can read about the XX handshake pattern here in the [Noise
Protocol specification document](http://noiseprotocol.org/noise.html).
XX allows for mutual authentication where the server sends their longterm
identity before the client does so.


# Usage

To import `mix_link`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
mix_link = "^0.2.0"
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

