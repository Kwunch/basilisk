use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;

use blake3::Hasher;
use serpent::cipher::{Block, BlockDecrypt, BlockEncrypt, Key, KeyInit};
use serpent::Serpent;

pub(crate) type BResult<T> = Result<T, Box<dyn Error>>;
pub(crate) struct Basilisk {
    key_size: usize,
    paths: Vec<PathBuf>,
    crypt: bool,
    verbose: bool,
    serpent: Serpent,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Basilisk {
    const BLOCK_SIZE: usize = 16;

    pub(crate) fn new(key_size: usize, paths: Vec<PathBuf>, crypt: bool, passphrase: String, verbose: bool) -> BResult<Self> {
        Ok(Self {
            key_size,
            paths,
            crypt,
            verbose,
            serpent: generate_key(key_size, passphrase)?,
            threads: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn run(&'static self) -> BResult<()> {
        /*
            * Run the Basilisk on the Given Path

            @param self: Basilisk Instance
            @return FResult: Result<(), Box<dyn Error>>
        */

        for path in &self.paths {
            let path = path.clone();
            match path.is_dir() {
                /* Iterate over the directory */
                true => {
                    if self.verbose {
                        println!("Got directory: {:?}", path);
                    }
                    /* Create new thread to run the directory */
                    {
                        let mut threads = self.threads.lock().unwrap();
                        threads.push(std::thread::spawn(move || {
                            self.iter_dir(path)
                                .expect("Failed to run directory");
                        }));
                    }
                }
                /* Modify the file */
                false => {
                    if self.verbose {
                        println!("Got file: {:?}", path);
                    }
                    self.modify_file(&path)?;
                }
            }
        }

        /* Wait for all threads to finish */
        loop {
            /* Lock the threads */
            let mut threads = self.threads.lock().unwrap();
            /* If there are are threads, pop the first, drop the lock, and join the thread */
            if threads.len() > 0 {
                /* Pop the first thread */
                let thread = threads.remove(0);
                /*
                    * Drop the lock before joining the thread
                    * Prevents deadlock if threads are still being spawned in run_dir()
                */
                drop(threads);
                /* Join the thread */
                thread.join().unwrap();
            } else {
                /* No threads left, break the loop (Lock drops on loop exit) */
                break;
            }
        }
        Ok(())
    }

    fn iter_dir(&'static self, path: PathBuf) -> BResult<()> {
        /*
            * Run the Basilisk on the Given Directory

            @param self: Basilisk Instance
            @param path: PathBuf
                * The path to the directory to encrypt or decrypt
            @return FResult: Result<(), Box<dyn Error>>
        */

        /* Iterate over the directory */
        for module in fs::read_dir(path)? {
            /* Get the module */
            let module = module?;

            match module.path().is_dir() {
                true => {
                    if self.verbose {
                        println!("Got subdirectory: {:?}", module.path());
                    }
                    /* Create new thread to run the subdirectory */
                    {
                        let mut threads = self.threads.lock().unwrap();
                        threads.push(std::thread::spawn(move || {
                            self.iter_dir(module.path())
                                .expect("Failed to run subdirectory");
                        }));
                    }
                }
                false => {
                    /* Modify the file */
                    /* On MAC, ignore .DS_Store */
                    if module.path().file_name().unwrap().eq(".DS_Store") {
                        continue;
                    }

                    if self.verbose {
                        println!("Got file: {:?}", module.path());
                    }

                    /* Run modify_file() on the file */
                    self.modify_file(&module.path())?;
                }
            }
        }

        Ok(())
    }

    fn modify_file(&'static self, path: &PathBuf) -> BResult<()> {
        /*
            * Modify [Encrypt or Decrypt] the Given File

            @param self: Basilisk Instance
            @param path: &PathBuf
                * The path to the file to encrypt or decrypt

            @return FResult: Result<(), Box<dyn Error>>
        */
        let mut file = File::open(path)?;
        let mut buffer: Vec<u8>;

        /* Read the file into blocks */
        let mut modified_blocks: Vec<Vec<u8>> = Vec::new();

        loop {
            /* Create a new buffer */
            buffer = vec![0; Self::BLOCK_SIZE];
            /* Read the buffer size from the file */
            let bytes_read = file.read(&mut buffer)?;

            if bytes_read == 0 {
                /* End of file, break the loop */
                break;
            }

            /* Convert the buffer to a vector */
            let mut block: Block<Serpent> = Block::<Serpent>::clone_from_slice(&buffer);

            match self.crypt {
                /* True -> Encrypt */
                true => self.serpent.encrypt_block(&mut block),
                /* False -> Decrypt */
                false => self.serpent.decrypt_block(&mut block),
            }
                /* Push the modified block to the vector */
                modified_blocks.push(block.to_vec());

        }

        /* Write the modified blocks to the file */
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)?;

        /* Iterate over the modified blocks writing each block */
        for block in &modified_blocks {
            if *block == modified_blocks.last().unwrap().to_vec() {
                /* Last block, clear padding */
                let mut padding = 0;
                for byte in block.iter().rev() {
                    if *byte == 0 {
                        padding += 1;
                    } else {
                        break;
                    }
                }
                /* Truncate the block */
                let block = &block[..block.len() - padding];
                file.write(&block)?;
                break;
            }

            file.write(&block)?;
        }

        Ok(())
    }
}

fn generate_key(key_size: usize, passphrase: String) -> BResult<Serpent> {
    let mut hasher = Hasher::new();
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();

    let key_size = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => {
            println!("Invalid key size");
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid key size")));
        }
    };

    let serpent =
        Serpent::new_from_slice(&*Key::<Serpent>::clone_from_slice(&hash.as_bytes()[..key_size])).expect("Failed to create Serpent");

    Ok(serpent)
}