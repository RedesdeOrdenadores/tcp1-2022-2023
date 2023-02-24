use std::{
    io::{Read, Write},
    net::{Ipv6Addr, SocketAddr, TcpListener},
};

use clap::Parser;
use tcp1::{Answer, Operation, TlvIterator};

#[derive(Debug, Parser)]
struct Args {
    /// Port number
    #[arg(value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.port)))?;
    let mut acc = 0i64;
    loop {
        let (mut stream, _addr) = listener.accept()?;
        let mut buffer = [0u8; 2048];
        loop {
            match stream.read(&mut buffer) {
                Ok(len) if len > 0 => {
                    for tlv in TlvIterator::process(&buffer[..len]) {
                        if let Ok(operation) = TryInto::<Operation>::try_into(tlv) {
                            let result = operation.reduce();
                            acc = acc.saturating_add(result);

                            stream.write_all(&Answer::from(acc).encode())?;
                            println!("{operation} = {result}");
                        } else {
                            eprintln!("Received a wrong operation.")
                        }
                    }
                }
                _ => break, // Probably the client has closed the connection
            }
        }
    }
}
