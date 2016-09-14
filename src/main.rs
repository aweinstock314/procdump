extern crate argparse;
extern crate libc;

use argparse::{ArgumentParser, Store};
use libc::{iovec, pid_t, process_vm_readv};
use std::slice;

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
}
