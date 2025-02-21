// SPDX-License-Identifier: GPL-3.0-or-later
/*
 *
 * Copyright (c) 2023–2025 Universidade de Vigo
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Miguel Rodríguez Pérez <miguel@det.uvigo.gal>
 *
 */

use std::{
    io::{Read, Write, stdin},
    net::{IpAddr, SocketAddr, TcpStream},
};

use clap::Parser;
use tcp1::{Answer, Operation, Tlv};

#[derive(Debug, Parser)]
struct Args {
    /// Destination IP Address
    ip: IpAddr,
    /// Destination port number
    #[arg(value_parser = clap::value_parser!(u16).range(1..))]
    dst_port: u16,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut buffer = [0u8; 2048];
    let mut stream = TcpStream::connect(SocketAddr::from((args.ip, args.dst_port)))?;

    println!("Enter arithmetic expressions using infix notation. For example: 10 * 3 or 5!.");

    for line in stdin().lines() {
        let iline = line?;
        if iline.trim() == "QUIT" {
            break;
        }
        match iline.parse::<Operation>() {
            Ok(operation) => {
                stream.write_all(&operation.encode())?;
                let len = stream.read(&mut buffer)?;
                let Answer(answer) = Tlv::try_from(&buffer[..len])?.try_into()?;
                println!("Accumulated value = {answer}");
            }
            Err(_) => println!("Could not parse operation. Please, try again."),
        }
    }

    Ok(())
}
