# Bitcoin protocol core library

![Build](https://github.com/BP-WG/bp-core/workflows/Build/badge.svg)
![Tests](https://github.com/BP-WG/bp-core/workflows/Tests/badge.svg)
![Lints](https://github.com/BP-WG/bp-core/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/BP-WG/bp-core/branch/master/graph/badge.svg)](https://codecov.io/gh/BP-WG/bp-core)

[![crates.io](https://img.shields.io/crates/v/bp-core)](https://crates.io/crates/bp-core)
[![Docs](https://docs.rs/bp-core/badge.svg)](https://docs.rs/bp-core)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/bp-core)](./LICENSE)

The library implements components necessary for working with Bitcoin 
consensus-level data structures and [client-side-validation] in bitcoin 
protocol, specifically

- deterministic bitcoin commitments API ([LNPBP-1], [LNPBP-2], [LNPBP-3], [LNPBP-6], [LNPBP-11] & [LNPBP-12] standards)
- bitcoin-based single-use-seal API ([LNPBP-10] standards)

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by [LNP/BP Standards Association][lnpbp-web]
([GitHub page][lnpbp-github]).

The original idea of client-side-validation was proposed by Peter Todd with its
possible applications designed by Giacomo Zucco. It was shaped into the protocol
design by Dr Maxim Orlovsky with an input from the community.

Minimum supported rust version for the library (MSRV) is 1.66 and 2021 rust
edition.


## Documentation

Detailed developer & API documentation for all libraries can be accessed at:
- <https://docs.rs/bp-core/>
- <https://docs.rs/bp-dbc/>
- <https://docs.rs/bp-seals/>
- <https://docs.rs/bp-consensus/>

To learn about the technologies enabled by the library please check
[slides from our tech presentations][presentations] and
[LNP/BP tech talks videos][lnpbp-youtube].


## Usage

The repository contains rust libraries for dealing with Bitcoin consensus-level
data and client-side validation.

### Use library in other projects

To use libraries, you just need latest version of libraries, published to
[crates.io](https://crates.io) into `[dependencies]` section of your project
`Cargo.toml`. Here is the full list of available libraries from this repository:

```toml
bp-consensus = "1" # Bitcoin protocol consensus crate
bp-dbc = "1" # Deterministic bitcoin commitments crate
bp-seals = "1" # Bitcoin single-use-seals crate
bp-core = "1" # Library including both of the previous crates
```

`bp-core` crate is an "umbrella" library containing all three libraries inside.

## Contributing

Contribution guidelines can be found in [CONTRIBUTING](CONTRIBUTING.md)

## More information

### MSRV

This library requires minimum rust compiler version (MSRV) 1.66.0.

### Policy on altcoins

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are
not supported and not planned to be supported; pull requests targeting them will
be declined.

### Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.


[lnpbp-web]: https://lnp-bp.org
[lnpbp-github]: https://github.com/LNP-BP
[lnpbp-youtube]: https://www.youtube.com/@LNPBP
[presentations]: https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/

[LNPBP-1]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0001.md
[LNPBP-2]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0002.md
[LNPBP-3]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0003.md
[LNPBP-6]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0006.md
[LNPBP-10]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0010.md
[LNPBP-11]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0011.md
[LNPBP-12]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0012.md
