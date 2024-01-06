use std::path::PathBuf;
use crate::basilisk::{Basilisk, BResult};

mod basilisk;

fn main() -> BResult<()> {
    let args: Vec<String> = std::env::args().collect();

    /* Encrypt or Decrypt? */
    let crypt = if args.contains(&String::from("--encrypt")) || args.contains(&String::from("-e")) {
        true
    } else if args.contains(&String::from("--decrypt")) || args.contains(&String::from("-d")) {
        false
    } else {
        print_usage();
        return Ok(());
    };

    let key_size = 128;
    /* If user specified a key size, use it, otherwise use 256 */
    //let key_size = if args.contains(&String::from("-k")) {
    //    let index = args.iter().position(|x| x == "-k").unwrap();
    //    let key_size = args[index + 1].parse::<usize>().unwrap();
    //    if key_size != 128 && key_size != 192 && key_size != 256 {
    //        print_usage();
    //        return Ok(());
    //    }
    //    key_size
    //} else {
    //    /* Default key size 256 */
    //    256
    //};

    /* Get all paths to encrypt or decrypt */
    let paths: Vec<&String> = if args.contains(&String::from("-p")) {
        let index = args.iter().position(|x| x == "-p").unwrap();
        let mut paths = Vec::new();
        paths.extend(&args[index + 1..]);
        paths
    } else {
        print_usage();
        return Ok(());
    };

    /* Check if all paths exist */
    let mut confirmed_paths: Vec<PathBuf> = Vec::new();
    for path in paths {
        let path = PathBuf::from(path);
        if !path.exists() {
            println!("Path {:?} does not exist", path);
        }
        confirmed_paths.push(path);
    }

    let passphrase = rpassword::prompt_password("Enter passphrase -> ").unwrap();

    let mut basilisk: &'static Basilisk = Box::leak(Box::new(Basilisk::new(key_size, confirmed_paths, crypt, passphrase, true).unwrap()));

    basilisk.run()?;

    Ok(())
}

fn print_usage() {
    println!("
        Usage: basilisk [--encrypt -e| --decrypt -d] -p <paths>
    ")
}
