extern crate argparse;
extern crate byteorder;
extern crate hex;
extern crate libc;
#[macro_use]
extern crate nom;

use argparse::{ArgumentParser, Store};
use byteorder::{BigEndian, ByteOrder};
use hex::FromHex;
use libc::{iovec, pid_t, process_vm_readv};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::ops::Range;
use std::slice;
use std::error::Error;
use nom::Producer;

// TODO: make a lifetime'd iovec wrapper? (this is unsafe as-is)
fn slice_to_iovec<T>(x: &mut [T]) -> iovec {
    iovec {
        iov_base: x.as_mut_ptr() as _,
        iov_len: x.len(),
    }
}

fn iovec_to_slice<'a, T>(x: iovec) -> &'a mut [T] {
    unsafe {
        slice::from_raw_parts_mut(x.iov_base as _, x.iov_len)
    }
}

//fn readmem(pid: pid_t, 

#[derive(Clone, Debug)]
struct Mapping {
    vmem: Range<usize>,
    perms: Vec<u8>,
    offset: usize,
    device: Vec<u8>,
    inode: Vec<u8>,
    pathname: Option<Vec<u8>>,
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
    use nom::{digit, space, FileProducer};
    named!(allmappings< &[u8], Vec<Mapping> >, separated_list!(is_a!("\r\n"), mapping));
    named!(nonspace< &[u8], &[u8] >, is_not!(" \t\r\n"));
    named!(hexstring< &[u8], usize >, map_res!(is_a!("0123456789abcdef"), |bytes: &[u8]| {
        let decodedbytes: Result<Vec<u8>, _> = FromHex::from_hex::<Vec<u8>>(bytes.into());
        let paddedbytes = decodedbytes.map(|x| if x.len() < 8 { let mut y = vec![0; 8-x.len()]; y.extend_from_slice(&x); y } else { x });
        paddedbytes.map(|x| BigEndian::read_u64(&x)).map(|x| x as usize)
    }));
    named!(mapping< &[u8], Mapping >, chain!(
        start: hexstring ~ tag!("-") ~ end: hexstring ~ space ~
        perms: nonspace ~ space ~
        offset: hexstring ~ space ~
        dev: nonspace ~ space ~
        inode: digit ~ space ~
        pathname: nonspace? ,
        || Mapping { vmem: Range { start: start, end: end }, perms: perms.into(), offset: offset, device: dev.into(), inode: inode.into(), pathname: pathname.map(|x| x.into()) }
    ));
    let filename = format!("/proc/{}/maps", pid);
    if !cfg!(avoid_producerconsumer) {
        let mut producer = try!(FileProducer::new(&filename, 4096));
        consumer_from_parser!(AllMappingsConsumer< Vec<Mapping> >, allmappings);
        let mut consumer = AllMappingsConsumer::new();
        Ok(producer.run(&mut consumer).map(|x| x.clone()).unwrap_or(vec![]))
    } else {
        let mut file = BufReader::new(try!(File::open(&filename)));
        let mut buf = vec![];
        try!(file.read_to_end(&mut buf));
        match allmappings(&buf) {
            nom::IResult::Done(_, o) => Ok(o),
            nom::IResult::Error(_) => Err("error".into()),
            nom::IResult::Incomplete(_) => Err("incomplete".into()),
        }
    }
}

fn main() {
    let mut pid: pid_t = 0;
    let mut to_read: (usize, usize) = (0xffffffffff600000, 0x1000); // hardcode vsyscall as a default
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Dump a process's memory");
        ap.refer(&mut pid).metavar("PID").add_argument("pid", Store, "The process id to dump").required();
        ap.refer(&mut to_read.0).metavar("ADDR").add_option(&["-a"], Store, "What address to read");
        ap.refer(&mut to_read.1).metavar("SIZE").add_option(&["-s"], Store, "How many bytes to read");
        ap.parse_args_or_exit();
    }
    let iov = iovec { iov_base: to_read.0 as _, iov_len: to_read.1 };
    let mut dest: Vec<u8> = vec![0; to_read.1];
    println!("Attempting to read {} bytes of memory from process {} starting at {:?}.", iov.iov_len, pid, iov.iov_base);
    let retval = unsafe { process_vm_readv(pid, &slice_to_iovec(&mut dest), 1, &iov, 1, 0) };
    println!("Result: {}, {:?}", retval, dest);
    println!("{:?}", read_mappings(pid));
}
