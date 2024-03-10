#[macro_use(crate_version)]
extern crate clap;

use std::env;

use clap::{Arg, ArgAction, ArgMatches, Command};
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::prelude::*;
use base64::prelude::*;
use clap::builder::Styles;
use clap::builder::styling::AnsiColor;


struct Config {
    message: String,
    decrypt: bool,
    salt: Option<Vec<u8>>,
    password: String,
}

impl Config {
    fn new(matches: &ArgMatches) -> Config {
        let message = matches.get_one::<String>("INPUT").unwrap().to_string();
        let decrypt = matches.get_flag("decrypt");
        let salt = match matches.get_one::<String>("salt") {
            Some(s) => Some(BASE64_STANDARD.decode(&s.to_string())
                .map(|s| s.to_vec()).expect("Invalid salt")),
            None => None
        };
        let password = matches.get_one::<String>("password").unwrap().to_string();

        Config { message, decrypt, salt, password }
    }
}

fn init_sp(v: usize, s: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8>;

    if s.len() > 0 {
        bytes = vec![0; v * ((s.len() + v - 1) / v)];
    } else {
        bytes = Vec::<u8>::new();
    }

    for (i, e) in bytes.iter_mut().enumerate() {
        *e = s[i % s.len()];
    }

    return bytes;
}

fn add_ib(a: &mut [u8], b: &[u8], offset: usize) {
    let mut x: u16 = b[b.len() - 1] as u16 + a[offset + b.len() - 1] as u16 + 1;

    a[offset + b.len() - 1] = x as u8;
    x >>= 8;

    let mut i = b.len() - 2;

    loop {
        x += b[i] as u16 + a[offset + i] as u16;
        a[offset + i] = x as u8;
        x >>= 8;

        if i == 0 {
            break;
        }

        i -= 1;
    }
}

fn derive_key(id: u8, size: usize, salt: &[u8], password: &[u8]) -> Vec<u8> {
    let key_size = size;
    let n = key_size / 8;
    let u = 256 / 8;
    let v = 512 / 8;
    let d: Vec<u8> = vec![id; v];
    let s = init_sp(v, salt);
    let p = init_sp(v, password);
    let mut i = s;

    i.extend(p);

    let mut b: Vec<u8> = vec![0; v];
    let mut a: Vec<u8> = vec![0; u];
    let mut d_key: Vec<u8> = vec![0; n];
    let c = (n + u - 1) / u;

    let mut l = 1;
    let iterations = 1000;

    let mut digest = Sha256::new();

    while l <= c {
        digest.input(&d);
        digest.input(&i);
        digest.result(&mut a);

        let mut j = 1;

        while j < iterations {
            digest.reset();
            digest.input(&a);
            digest.result(&mut a);
            j += 1;
        }

        let mut j = 1;

        while j != b.len() {
            b[j] = a[j % a.len()];
            j += 1;
        }

        let mut j = 0;

        while j != i.len() / v {
            add_ib(&mut i, &b, j * v);
            j += 1;
        }

        if l == c {
            let mut k = 0;

            while k < d_key.len() - ((l - 1) * u) {
                d_key[(l - 1) * u + k] = a[k];
                k += 1;
            }
        } else {
            let mut k = 0;

            while k < a.len() {
                d_key[(l - 1) * u + k] = a[k];
                k += 1;
            }
        }

        l += 1;
    }

    return d_key;
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn format_password(password: &String) -> Vec<u8> {
    let mut formatted_password = vec![0; (password.len() + 1) * 2];

    for (i, c) in password.as_bytes().iter().enumerate() {
        formatted_password[i * 2 + 1] = *c;
    }

    return formatted_password;
}

fn do_decrypt(config: &Config) -> Vec<u8> {
    let formatted_password = format_password(&config.password);
    let bytes = BASE64_STANDARD.decode(&config.message).unwrap();
    let ref salt = &bytes[..16];
    let ref message = &bytes[16..];
    let key = derive_key(1, 256, salt, &formatted_password);
    let iv = derive_key(2, 128, salt, &formatted_password);

    return decrypt(&message[..], &key, &iv).ok().unwrap();
}

fn do_encrypt(config: &Config) -> String {
    let formatted_password = format_password(&config.password);
    let salt: Vec<u8> = config.salt.clone().unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        let mut s = vec![0; 16];
        rng.fill_bytes(&mut s);
        s
    });

    let key = derive_key(1, 256, &salt, &formatted_password);
    let iv = derive_key(2, 128, &salt, &formatted_password);
    let mut encrypted_data = Vec::<u8>::new();
    let encrypted_message = encrypt(&config.message.as_bytes(), &key, &iv).ok().unwrap();

    encrypted_data.extend(salt);
    encrypted_data.extend(encrypted_message);

    return BASE64_STANDARD.encode(&encrypted_data);
}

fn parse_args(args: &Vec<String>) -> ArgMatches {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Green.on_default());

    Command::new("pbetool")
        .styles(styles)
        .about("Password Based Encryption Tool")
        .version(crate_version!())
        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .action(ArgAction::SetTrue)
            .help("Decrypt instead of encrypt"))
        .arg(Arg::new("password")
            .short('p')
            .long("password")
            .required(true)
            .help("A password"))
        .arg(Arg::new("salt")
            .short('s')
            .long("salt")
            .help("A Base64 encoded salt"))
        .arg(Arg::new("INPUT")
            .help("Sets the input to use")
            .required(true)
            .index(1))
        .get_matches_from(args)
}

fn main() {
    let args = env::args().collect();
    let config = Config::new(&parse_args(&args));

    if config.decrypt {
        println!("{}", String::from_utf8(do_decrypt(&config)).unwrap());
    } else {
        println!("{}", do_encrypt(&config));
    }
}

