// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{self, Duration};
use std::vec::IntoIter;

use self::dns::{Dns, DnsQuery};

use std::net::UdpSocket;

mod dns;

const EINVAL: i32 = 22;

#[derive(Debug)]
pub struct LookupHost(IntoIter<SocketAddr>);

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

pub fn lookup_host(host: &str) -> Result<LookupHost> {
    let ip_string = "0.0.0.0";
    let ip: Vec<u8> = ip_string.trim().split(".").map(|part| part.parse::<u8>()
                               .unwrap_or(0)).collect();

    let dns_string = "8.8.8.8";
    let dns: Vec<u8> = dns_string.trim().split(".").map(|part| part.parse::<u8>()
                                 .unwrap_or(0)).collect();

    if ip.len() == 4 && dns.len() == 4 {
        let time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
        let tid = (time.subsec_nanos() >> 16) as u16;

        let packet = Dns {
            transaction_id: tid,
            flags: 0x0100,
            queries: vec![DnsQuery {
                name: host.to_string(),
                q_type: 0x0001,
                q_class: 0x0001,
            }],
            answers: vec![]
        };

        let packet_data = packet.compile();

        let my_ip = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
        let dns_ip = Ipv4Addr::new(dns[0], dns[1], dns[2], dns[3]);
        let socket = UdpSocket::bind(&SocketAddr::V4(SocketAddrV4::new(my_ip, 0)))?;
        socket.set_read_timeout(Some(Duration::new(5, 0)))?;
        socket.set_write_timeout(Some(Duration::new(5, 0)))?;
        socket.connect(&SocketAddr::V4(SocketAddrV4::new(dns_ip, 53)))?;
        socket.send(&packet_data)?;

        let mut buf = [0; 65536];
        let count = socket.recv(&mut buf)?;

        match Dns::parse(&buf[.. count]) {
            Ok(response) => {
                let mut addrs = vec![];
                for answer in response.answers.iter() {
                    if answer.a_type == 0x0001 && answer.a_class == 0x0001
                       && answer.data.len() == 4
                    {
                        let answer_ip = Ipv4Addr::new(answer.data[0],
                                                      answer.data[1],
                                                      answer.data[2],
                                                      answer.data[3]);
                        addrs.push(SocketAddr::V4(SocketAddrV4::new(answer_ip, 0)));
                    }
                }
                Ok(LookupHost(addrs.into_iter()))
            },
            Err(_err) => Err(Error::from_raw_os_error(EINVAL))
        }
    } else {
        Err(Error::from_raw_os_error(EINVAL))
    }
}

fn main() {
    println!("{:#?}", lookup_host("www.lua.org"));
}
