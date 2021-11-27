# Bitcoin protocol core library

![Build](https://github.com/LNP-BP/bp-core/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/bp-core/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/bp-core/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/bp-core/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/bp-core)

[![crates.io](https://img.shields.io/crates/v/bp-core)](https://crates.io/crates/bp-core)
[![Docs](https://docs.rs/bp-core/badge.svg)](https://docs.rs/bp-core)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/bp-core)](./LICENSE)

The library implements bitcoin protocol elements which are missed from other
existing bitcoin libraries, like [rust-bitcoin] and [descriptor wallet].
Currently, it includes components necessary for [client-side-validation] over
bitcoin, specifically
- deterministic bitcoin commitments API (LNPBP-14, 6 standards)
- bitcoin-based single-use-seal API (LNPBP-10 and LNPBP-39 standards)

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by [LNP/BP Standards Association](https://lnp-bp.org).


## Usage

To use libraries, you just need latest version of libraries, published to 
[crates.io](https://crates.io) into `[dependencies]` section of your project 
`Cargo.toml`. Here is the full list of available libraries from this repository:

```toml
bp-dbc = "0.5" # Deterministic bitcoin commitments crate
bp-seals = "0.5" # Bitcoin single-use-seals crate
bp-core = "0.5" # Library including both of the previous crates
```

`bp-core` crate is an "umbrella" library containing both deterministic bitcoin
commitments and bitcoin seals crates inside.


## Known applications

The current list of the projects based on the library include:
* [RGB](https://github.com/LNP-BP/rgb-node): Confidential & scalable smart
  contracts for Bitcoin & Lightning
* [Bitcoin-based decentralized identity](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2021-February/018381.html) 
  proposal uses single-use-seals


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](CONTRIBUTING.md)


## More information

### Policy on altcoins

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are 
not supported and not planned to be supported; pull requests targeting them will 
be declined.

### Licensing

See [LICENCE](LICENSE) file.


[rust-bitcoin]: https://github.com/rust-bitcoin/rust-bitcoin
[descriptor-wallet]: https://github.com/LNP-BP/descriptor-wallet
[client-side-validation]: https://docs.rs/client_side_validation/
