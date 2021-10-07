[![docs.rs](https://docs.rs/crypto_api_blake2/badge.svg)](https://docs.rs/crypto_api_blake2)
[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/crypto_api_blake2.svg)](https://crates.io/crates/crypto_api_blake2)
[![Download numbers](https://img.shields.io/crates/d/crypto_api_blake2.svg)](https://crates.io/crates/crypto_api_blake2)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/crypto_api_blake2?svg=true)](https://ci.appveyor.com/project/KizzyCode/crypto-api-blake2)
[![dependency status](https://deps.rs/crate/crypto_api_blake2/0.2.0/status.svg)](https://deps.rs/crate/crypto_api_blake2/0.2.0)


# crypto_api_blake2
Welcome to `crypto_api_blake2` 🎉


## About
This crate implements [Blake2b](https://blake2.net/blake2.pdf) with APIs for various use-cases:
 - Streaming and oneshot variable length hash algorithm (obviously)
 - Streaming and oneshot message authentication code (= keyed hash with secure finalization to
   prevent [length extension attacks](https://en.wikipedia.org/wiki/Length_extension_attack))
 - Salt- and info-based KDF


## Security
⚠️ Some words of warning ahead: This library is beta and has not been audited yet – use at your
own risk! ⚠️

However we try to do things right from the start – this library is
[KISS](https://en.wikipedia.org/wiki/KISS_principle) and tested against various test vectors.

### Test Vectors
All implementations pass all reference test vectors and are assumed to produce correct results even
in corner cases – we also use API test vectors to test our input validation.

### Memory Hygiene
`crypto_api_blake2` does not perform any attempts to erase sensitive contents from memory. However,
all sensitive contents are stored in heap-allocated memory, so if you're using an erasing
memory-allocator like [MAProper](https://crates.io/crates/ma_proper) they will be erased nontheless.

Using an erasing memory allocator is a good idea anyway, because Rust makes it pretty hard to keep
track on how the memory is managed under the hood – the memory allocator on the other hand sees
everything that happens on the heap and can take care of it accordingly.


## Dependencies
Because this code implements the [`crypto_api`](https://github.com/KizzyCode/crypto_api), it depends
on the `crypto_api`-crate. Otherwise, it's dependency less.