use std::{
    io::{stdin, Read, Write},
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

    for line in stdin().lines() {
        let iline = line?;
        if iline.trim() == "QUIT" {
            break;
        }
        match iline.parse::<Operation>() {
            Ok(operation) => {
                stream.write_all(&operation.encode())?;
                let len = stream.read(&mut buffer)?;
                let answer = Answer::try_from(Tlv::try_from(&buffer[..len])?)?;
                println!("{} = {}", operation, answer.num);
            }
            Err(_) => println!("Could not parse operation. Please, try again."),
        }
    }

    Ok(())
}
