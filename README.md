# A Possible Implementation of the Remote TCP-Based Calculator Exercise for the Computer Networks Subject

[![Build Status](https://github.com/RedesdeOrdenadores/tcp1-2022-2023/actions/workflows/build.yml/badge.svg)](https://github.com/migrax/tcp1-2022-2023/actions/workflows/build.yml)

## Overview

This is a Rust language implementation for a programming task of the [Computer
Networks subject][CN] of the [Bachelor Degree in Telecommunication Technologies
Engineering][BTTE] of the [Universidade de Vigo][uvigo].

As the exercise involves a very basic socket communication scenario, the code
tries to provide a minimally satisfactory solution without consideration to
performance or security whatsoever.

## About the Code

The client and server programs are contained in the files
[tcp1cli.rs](src/bin/tcp1cli.rs) and [tcp2ser.rs](src/bin/tcp1ser.rs). They make
use of a little library for parsing the arithmetic operations both from the user
and from/to the network.

The file [operations.rs](src/operation.rs) defines the allowed set of arithmetic
operations, the functions to calculate them and all the conversions needed: from
TLV fields and to from strings for exchanging data with the user.

Finally, a set of utilities for managing TLVs are provided in the file
[tlv.rs](src/tlv.rs).

All the encoding and decoding methods have been performed manually, instead of
using a crate like [serde][serde] as this was something that students are
expected to learn how to do it in this exercise. Obviously, if this were not an
exercise, it would have been more adequate to not try to reinvent the wheel.

### Dependencies

Even if the spirit was to do as much of the code ourselves, we have used some
dependencies for the tasks not directly related with the communication problem.
The list is as follows:

* [anyhow][anyhow] and [thiserror][thiserror]: For easy error management and
      definition, respectively.
* [clap][clap]: To parse command line arguments.
* [regex][regex]: To parse the operations as entered by the user
* [socket2][socket2]: We needed to use this low-level socket library in the
      server to make the Windows version of the program behave like the Linux
      one. We use a IPV6 socket on the server to accept both IPv4 and IPv6
      connections. Under Linux this works by default, but in windows this has to
      be enabled manually. Two alternative solutions would have been:
  * Ignoring the issue and accepting only IPv6 connections under Windows,
  * use simultaneous sockets in the server, but this complicates the code so much.

---
#### Legal:
Copyright ⓒ 2023–2025 [Universidade de Vigo][uvigo].<br>
Author: Miguel Rodríguez Pérez <miguel@det.uvigo.gal>.<br>
This software is licensed under the GNU General Public License, version 3 (GPL-3.0) or later. For information see LICENSE.

[uvigo]: https://www.uvigo.gal/
[BTTE]: https://teleco.uvigo.es/estudos/graos/bachelor-degree-in-telecommunication-technologies-engineering/
[CN]: https://secretaria.uvigo.gal/docnet-nuevo/guia_docent/index.php?centre=305&ensenyament=V05G306V01&assignatura=V05G306V01210&idioma=eng
[serde]: https://serde.rs/
[anyhow]: https://crates.io/crates/anyhow
[thiserror]: https://crates.io/crates/thiserror
[socket2]: https://crates.io/crates/socket2
[regex]: https://crates.io/crates/regex
[clap]: https://crates.io/crates/regex
