#[macro_use] extern crate nom;
extern crate argparse;
extern crate byteorder;
extern crate hex;
extern crate libc;
extern crate rand;
extern crate time;

use argparse::{ArgumentParser, Store, StoreOption};
use byteorder::{BigEndian, ByteOrder};
use hex::{FromHex, ToHex};
use libc::{iovec, perror, pid_t, process_vm_readv, process_vm_writev};
use nom::Producer;
use rand::Rng;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::ops::Range;
use time::{Duration, get_time};
use rand::distributions::{Sample, Weighted, WeightedChoice};

// TODO: make a lifetime'd iovec wrapper? (this is unsafe as-is)
fn slice_to_iovec<T>(x: &mut [T]) -> iovec {
    iovec {
        iov_base: x.as_mut_ptr() as _,
        iov_len: x.len(),
    }
}

#[derive(Clone, Debug)]
struct Mapping {
    vmem: Range<usize>,
    perms: Vec<u8>,
    offset: usize,
    device: Vec<u8>,
    inode: Vec<u8>,
    pathname: Option<String>,
}

fn format_as_string(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes).unwrap_or("").into()
}

impl Display for Mapping {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "Mapping {{ Range {{ start: {:x}, end: {:x} }}, perms: {}, offset: {}, device: {}, inode: {}, pathname: {:?} }}",
            self.vmem.start, self.vmem.end,
            format_as_string(&self.perms), self.offset, format_as_string(&self.device), format_as_string(&self.inode), self.pathname)
    }
}

fn read_mappings(pid: pid_t) -> Result<Vec<Mapping>, Box<Error>> {
/*
$ cat /proc/self/maps
00400000-0040c000 r-xp 00000000 08:01 14417934                           /bin/cat
0060b000-0060c000 r--p 0000b000 08:01 14417934                           /bin/cat
0060c000-0060d000 rw-p 0000c000 08:01 14417934                           /bin/cat
00ee4000-00f05000 rw-p 00000000 00:00 0                                  [heap]
7f51bf591000-7f51bf733000 r-xp 00000000 08:01 12454654                   /lib/x86_64-linux-gnu/libc-2.19.so
7f51bf733000-7f51bf932000 ---p 001a2000 08:01 12454654                   /lib/x86_64-linux-gnu/libc-2.19.so
7f51bf932000-7f51bf936000 r--p 001a1000 08:01 12454654                   /lib/x86_64-linux-gnu/libc-2.19.so
7f51bf936000-7f51bf938000 rw-p 001a5000 08:01 12454654                   /lib/x86_64-linux-gnu/libc-2.19.so
7f51bf938000-7f51bf93c000 rw-p 00000000 00:00 0
7f51bf93c000-7f51bf95c000 r-xp 00000000 08:01 12454651                   /lib/x86_64-linux-gnu/ld-2.19.so
7f51bf999000-7f51bf9bb000 rw-p 00000000 00:00 0
7f51bf9bb000-7f51bfb44000 r--p 00000000 08:01 10617966                   /usr/lib/locale/locale-archive
7f51bfb44000-7f51bfb47000 rw-p 00000000 00:00 0
7f51bfb5a000-7f51bfb5c000 rw-p 00000000 00:00 0
7f51bfb5c000-7f51bfb5d000 r--p 00020000 08:01 12454651                   /lib/x86_64-linux-gnu/ld-2.19.so
7f51bfb5d000-7f51bfb5e000 rw-p 00021000 08:01 12454651                   /lib/x86_64-linux-gnu/ld-2.19.so
7f51bfb5e000-7f51bfb5f000 rw-p 00000000 00:00 0
7ffc5492c000-7ffc5494d000 rw-p 00000000 00:00 0                          [stack]
7ffc549c2000-7ffc549c4000 r-xp 00000000 00:00 0                          [vdso]
7ffc549c4000-7ffc549c6000 r--p 00000000 00:00 0                          [vvar]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
*/
    use nom::{digit, eof, multispace, space, FileProducer};
    named!(allmappings< &[u8], Vec<Mapping> >, chain!(x: separated_list!(is_a!("\r\n"), mapping) ~ multispace? ~ eof?, || x));
    named!(nonspace< &[u8], &[u8] >, is_not!(" \t\r\n"));
    named!(hexstring< &[u8], usize >, map_res!(is_a!("0123456789abcdef"), |bytes: &[u8]| {
        FromHex::from_hex::<Vec<u8>>(bytes.into())
            .map(|x: Vec<u8>| if x.len() < 8 { let mut y = vec![0; 8-x.len()]; y.extend_from_slice(&x); y } else { x })
            .map(|x| BigEndian::read_u64(&x)).map(|x| x as usize)
    }));
    named!(mapping< &[u8], Mapping >, chain!(
        start: hexstring ~ tag!("-") ~ end: hexstring ~ space ~
        perms: nonspace ~ space ~
        offset: hexstring ~ space ~
        dev: nonspace ~ space ~
        inode: digit ~ space ~
        pathname: nonspace? ,
        || Mapping {
            vmem: Range { start: start, end: end },
            perms: perms.into(), offset: offset, device: dev.into(), inode: inode.into(),
            pathname: pathname.and_then(|x| std::str::from_utf8(x).ok()).map(|x| x.into()) }
    ));
    fn logging_allmappings(x: &[u8]) -> nom::IResult<&[u8], Vec<Mapping>> {
        //println!("allmappings's input: {:?}", std::str::from_utf8(&x));
        let result = allmappings(x);
        //println!("allmappings's result: {:?}", result);
        result
    }
    let filename = format!("/proc/{}/maps", pid);
    //let filename = format!("tmpmaps");
    let result = if cfg!(feature="use_producerconsumer") {
        // this seems to be buggy (doesn't read until EOF consistently, seems to stop at 4046 chars when 
        //  reading a python REPL's maps, which leads to missing stack/vdso/vsyscall)
        let mut producer = try!(FileProducer::new(&filename, 8192));
        consumer_from_parser!(AllMappingsConsumer< Vec<Mapping> >, logging_allmappings);
        let mut consumer = AllMappingsConsumer::new();
        /*println!("{:?}", producer.run(&mut consumer).map(|x| x.clone()).unwrap_or(vec![]));
        let mut consumer = AllMappingsConsumer::new();
        println!("{:?}", producer.run(&mut consumer).map(|x| x.clone()).unwrap_or(vec![]));
        let mut consumer = AllMappingsConsumer::new();
        println!("{:?}", producer.run(&mut consumer).map(|x| x.clone()).unwrap_or(vec![]));*/
        Ok(producer.run(&mut consumer).map(|x| x.clone()).unwrap_or(vec![]))
        //Err("foo".into())
    } else {
        let mut file = BufReader::new(try!(File::open(&filename)));
        let mut buf = vec![];
        try!(file.read_to_end(&mut buf));
        //println!("{}", buf.len());
        //if let Ok(s) = std::str::from_utf8(&buf) { println!("{}", s); } else { println!("{:?}", buf); }
        match logging_allmappings(&buf) {
            nom::IResult::Done(_, o) => Ok(o),
            nom::IResult::Error(e) => Err(format!("Error {:?}", e).as_str().into()),
            nom::IResult::Incomplete(e) => Err(format!("Incomplete {:?}", e).as_str().into()),
        }
    };
    if let Err(ref e) = result {
        println!("{}", e);
    }
    result
}

fn readmem(pid: pid_t, sources: &[(usize, usize)]) -> Result<Vec<Vec<u8>>, ()> {
    let riovecs: Vec<_> = sources.iter().map(|&(ptr, size)| iovec { iov_base: ptr as _, iov_len: size as _ }).collect();
    let mut dests: Vec<Vec<u8>> = vec![vec![]; sources.len()];
    let liovecs: Vec<_> = dests.iter_mut().zip(sources.iter()).map(|(vec, &(_, size))| {
        vec.resize(size, 0);
        slice_to_iovec(&mut vec[..])
    }).collect();
    let retval = unsafe { process_vm_readv(pid, liovecs.as_ptr(), liovecs.len() as u64, riovecs.as_ptr(), riovecs.len() as u64, 0) };
    if retval < 0 {
        Err(())
    } else {
        Ok(dests)
    }
}

fn dump_process_memory(pid: pid_t, address: usize, size: usize) {
    {
        println!("Attempting to read {} bytes of memory from process {} starting at {:x}.", size, pid, address);
        if let Ok(dests) = readmem(pid, &[(address, size)]) {
            println!("Result: '{}'", ToHex::to_hex(&dests[0]));
        } else {
            println!("Failed to read memory.");
        }
    }

        if let Ok(mappings) = read_mappings(pid) {
        let mut readpairs = vec![];
        for mapping in mappings.iter() {
            println!("{}", mapping);
            let size = mapping.vmem.end - mapping.vmem.start;
            //if size < 0x2000 {
                readpairs.push((mapping.vmem.start, size));
            //}
        }
        println!("{:?}", readpairs);
        for (ptr,size) in readpairs {
            if let Ok(dests) = readmem(pid, &[(ptr,size)]) {
                /*for (dest, (ptr,size)) in dests.iter().zip(readpairs) {
                    println!("{:x}, {:x}: '{}'", ptr, size, ToHex::to_hex(&dest));
                }*/
                println!("{:x}, {:x}: '{}'", ptr, size, ToHex::to_hex(&dests[0]));
                println!("-----");
            }
        }
    }
}

fn random_bitflips(pid: pid_t, ns: i64, probability_of_bitflip: f64, only_substring: Option<String>) {
    if let Ok(mappings) = read_mappings(pid) {
        let time_per_potential_bitflip = Duration::nanoseconds(ns);
        let mut rng = rand::thread_rng();
        let mut byte = 0u8;

        let total_size: usize = mappings.iter().map(|m| m.vmem.end - m.vmem.start).sum();
        let mut weights: Vec<_> = mappings.iter().enumerate().map(|(i, m)| {
            let size: usize = m.vmem.end - m.vmem.start;
            let sizefrac: f64 = (size as f64) / (total_size as f64);
            Weighted {
                weight: (sizefrac * (u32::max_value() as f64)) as u32,
                item: i,
            }
        }).collect();
        let mut distribution = WeightedChoice::new(&mut weights);

        let mut last_time = get_time();
        loop {
            let cur_time = get_time();
            let elapsed = cur_time - last_time;
            if elapsed >= time_per_potential_bitflip {
                last_time = cur_time;
                if rng.gen_range(0.0, 1.0) < probability_of_bitflip {
                    let mapping = (|| { loop {
                        //let mapping = &mappings[rng.gen_range(0, mappings.len())];
                        let mapping = &mappings[distribution.sample(&mut rng)];
                        //println!("{:?}", mapping);
                        if !mapping.perms.contains(&b'w') {
                            continue;
                        }
                        match (only_substring.as_ref(), mapping.pathname.as_ref()) {
                            (Some(ref substr), Some(ref pathname)) => {
                                let substr: &str = substr;
                                if !pathname.contains(&substr) {
                                    continue;
                                }
                                println!("{}", pathname);
                            }
                            (None, _) => (),
                            (Some(_), None) => continue,
                        }
                        return mapping;
                    }})();
                    let their_iov = iovec {
                        iov_base: rng.gen_range(mapping.vmem.start, mapping.vmem.end) as _,
                        iov_len: 1,
                    };
                    let our_iov = iovec {
                        iov_base: &mut byte as *mut u8 as _,
                        iov_len: 1,
                    };
                    unsafe { if process_vm_readv(pid, &our_iov, 1, &their_iov, 1, 0) < 0 {
                        perror(b"readv failed\0".as_ptr() as _);
                        return;
                    }}
                    print!("Attempting to change {:016p} in pid {} from {:02x} to ", their_iov.iov_base, pid, byte);
                    byte ^= 1 << rng.gen_range(0,8);
                    println!("{:02x}", byte);
                    unsafe { if process_vm_writev(pid, &our_iov, 1, &their_iov, 1, 0) < 0 {
                        perror(b"writev failed\0".as_ptr() as _);
                        return;
                    }}

                }
            }
        }
    } else {
        println!("Failed to read/parse /proc/{}/maps", pid);
    }
}

fn main() {
    let mut pid: pid_t = 0;
    let mut command: String = "".into();
    // hardcode vsyscall as a default
    let mut address: usize = 0xffffffffff600000;
    let mut size: usize = 0x1000;
    let mut ns_per_bitflip = 800000; // trial and error for "takes a few seconds to kill cat"
    let mut prob_of_bitflip = 0.1;
    let mut substr = None;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Dump (or poke) a process's memory");
        ap.refer(&mut command).metavar("COMMAND").add_argument("command", Store, "The command to run {\"dump\",\"bitflip\"}").required();
        ap.refer(&mut pid).metavar("PID").add_argument("pid", Store, "The process id to dump").required();
        ap.refer(&mut address).metavar("ADDR").add_option(&["-a"], Store, "What address to read");
        ap.refer(&mut size).metavar("SIZE").add_option(&["-s"], Store, "How many bytes to read");
        ap.refer(&mut ns_per_bitflip).metavar("TIME").add_option(&["-t"], Store, "How many time in nanoseconds per bitflip chance");
        ap.refer(&mut prob_of_bitflip).metavar("PROBABILITY").add_option(&["-p"], Store, "What probability to flip bits with");
        ap.refer(&mut substr).add_option(&["--mapsubstr"], StoreOption, "Substring of path to search for");
        ap.parse_args_or_exit();
    }

    match &*command {
        "dump" => dump_process_memory(pid, address, size),
        "bitflip" => random_bitflips(pid, ns_per_bitflip, prob_of_bitflip, substr),
        x => {
            println!("Unknown command: \"{}\"", x);
        },
    }
}
