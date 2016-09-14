extern crate argparse;
extern crate libc;

use argparse::{ArgumentParser, Store};
use libc::{iovec, pid_t, process_vm_readv};

// TODO: make a lifetime'd iovec wrapper? (this is unsafe as-is)
fn slice_to_iovec<T>(x: &mut [T]) -> iovec {
    iovec {
        iov_base: x.as_mut_ptr() as _,
        iov_len: x.len(),
    }
}

//fn readmem(pid: pid_t, 

fn main() {
    let mut pid: pid_t = 0;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Dump a process's memory");
        ap.refer(&mut pid).metavar("PID").add_argument("pid", Store, "the process id to dump").required();
        ap.parse_args_or_exit();
    }
    println!("Attempting to read memory from process {}.", pid);
}
