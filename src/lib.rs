use samp::initialize_plugin;
use samp::native;

use samp::error::AmxError;
use samp::prelude::*;

use samp::amx::AmxIdent;
use samp::plugin::SampPlugin;

use std::collections::LinkedList;

use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

use threadpool::ThreadPool;

use log::info;
use log::error;

use argon2::Config;
use argon2::Variant;
use argon2::Version;

use argon2::hash_encoded;
use argon2::verify_encoded;

use chardetng::EncodingDetector;

#[derive(Debug)]
enum ArgumentTypes
{
    Primitive(i32),
    String(Vec<u8>)
}

type HashParams = (i32, String, String, Vec<ArgumentTypes>);
type VerifyParams = (i32, String, bool, Vec<ArgumentTypes>);

initialize_plugin!(
    natives: [
        SampArgon2::argon2_hash,
        SampArgon2::argon2_get_hash,
        SampArgon2::argon2_verify
    ],
    {
        samp::plugin::enable_process_tick();

        let samp_logger = samp::plugin::logger()
            .level(log::LevelFilter::Info);

        let _ = fern::Dispatch::new()
            .format(|callback, message, record| {
                callback.finish(format_args!("[SampArgon2] [{}]: {}", record.level().to_string().to_lowercase(), message))
            })
            .chain(samp_logger)
            .apply();

        SampArgon2 {
            hashes: LinkedList::new(),
            pool: ThreadPool::new(3),
            amx_list:Vec::new(),
            hash_receiver:None,
            hash_sender:None,
            verify_receiver:None,
            verify_sender:None
        }
    }
);

impl SampArgon2 {
    #[native(raw, name = "argon2_hash")]
    fn argon2_hash(&mut self, amx: &Amx, mut args: samp::args::Args) -> AmxResult<bool> {
        let playerid = args.next::<i32>().ok_or(AmxError::Params)?;
        let callback = args.next::<AmxString>().ok_or(AmxError::Params)?.to_string();
        let pass = args.next::<AmxString>().ok_or(AmxError::Params)?.to_string();
        let salt = args.next::<AmxString>().ok_or(AmxError::Params)?.to_string();
        let variant = args.next::<u32>().ok_or(AmxError::Params)?;
        let mem_cost = args.next::<u32>().ok_or(AmxError::Params)?;
        let time_cost = args.next::<u32>().ok_or(AmxError::Params)?;
        let lanes = args.next::<u32>().ok_or(AmxError::Params)?;
        let hash_length = args.next::<u32>().ok_or(AmxError::Params)?;

        let mut format: Vec<u8> = Vec::new();
        
        if args.count() > 4 {
            if let Some(specifiers) = args.next::<AmxString>() {
                format = specifiers.to_bytes();
            }
        }

        if !format.is_empty() && format.len() != args.count() - 10 {
            error!("The argument count mismatch expected :{} provided: {}.", format.len(), args.count() - 10);
            return Ok(false);
        }

        let sender = self.hash_sender.clone();
        let mut optional_args: Vec<ArgumentTypes> = Vec::new();

        for specifiers in format {
            match specifiers {
                b'd' | b'i' | b'f' => {
                    optional_args.push(ArgumentTypes::Primitive(*args.next::<Ref<i32>>().ok_or(AmxError::Params)?));
                }
                b's' => {
                    let argument: Ref<i32> = args.next().ok_or(AmxError::Params)?;
                    let amx_str = AmxString::from_raw(amx, argument.address())?;
                    optional_args.push(ArgumentTypes::String(amx_str.to_bytes()));
                }
                _ => {
                    error!("Unknown specifier type {}", specifiers);
                    return Ok(false);
                }
            }
        }

        let config = Config {
            ad: &[],
            hash_length: hash_length,
            lanes: lanes,
            mem_cost: mem_cost,
            secret: &[],
            time_cost: time_cost,
            variant: Variant::from_u32(variant).unwrap(),
            version: Version::Version13
        };

        let mut new = EncodingDetector::new();

        let feed = EncodingDetector::feed(&mut new, format!("{}{}", pass, salt).as_bytes(), false);

        let guess = EncodingDetector::guess(&new, Some(b"com"), feed);

        let pass = String::from(guess.decode(pass.as_bytes()).0.clone());
        let salt = String::from(guess.decode(salt.as_bytes()).0.clone());

        self.pool.execute(move || {
            match hash_encoded(pass.as_bytes(), salt.as_bytes(), &config) {
                Ok(hashed) => {
                    let _ = sender.as_ref().unwrap().send((playerid, callback, hashed, optional_args));
                }
                Err(err) => {
                    error!("{} => {:?}", callback, err);
                }
            }
        });

        Ok(true)
    }

    #[native(name = "argon2_get_hash")]
    fn argon2_get_hash(&mut self, _amx: &Amx, dest: UnsizedBuffer, size: usize) -> AmxResult<bool> {
        match self.hashes.front() {
            Some(hash) => {
                let mut dest = dest.into_sized_buffer(size);
                let _ = samp::cell::string::put_in_buffer(&mut dest, hash);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    #[native(raw, name = "argon2_verify")]
    fn argon2_verify(&mut self, amx: &Amx, mut args: samp::args::Args) -> AmxResult<bool> {
        let playerid = args.next::<i32>().ok_or(AmxError::Params)?;
        let callback = args.next::<AmxString>().ok_or(AmxError::Params)?.to_string();
        let pass = args.next::<AmxString>().ok_or(AmxError::Params)?.to_string();
        let hash = args.next::<AmxString>().ok_or(AmxError::Params)?.to_string();

        let mut format: Vec<u8> = Vec::new();

        if args.count() > 4 {
            if let Some(specifiers) = args.next::<AmxString>() {
                format = specifiers.to_bytes();
            }
        }

        if !format.is_empty() && format.len() != args.count() - 5 {
            error!("The argument count mismatch expected :{} provided: {}.", format.len(), args.count() - 5);
            return Ok(false);
        }

        let sender = self.verify_sender.clone();
        let mut optional_args: Vec<ArgumentTypes> = Vec::new();

        for specifiers in format {
            match specifiers {
                b'd' | b'i' | b'f' => {
                    optional_args.push(ArgumentTypes::Primitive(
                        *args.next::<Ref<i32>>().ok_or(AmxError::Params)?
                    ));
                }
                b's' => {
                    let argument: Ref<i32> = args.next().ok_or(AmxError::Params)?;
                    let amx_str = AmxString::from_raw(amx, argument.address())?;
                    optional_args.push(ArgumentTypes::String(amx_str.to_bytes()));
                }
                _ => {
                    error!("Unknown specifier type {}", specifiers);
                    return Ok(false);
                }
            }
        }

        let mut new = EncodingDetector::new();

        let feed = EncodingDetector::feed(&mut new, pass.as_bytes(), false);

        let guess = EncodingDetector::guess(&new, Some(b"com"), feed);

        let pass = String::from(guess.decode(pass.as_bytes()).0.clone());

        self.pool.execute(move || {
            match verify_encoded(&hash, pass.as_bytes()) {
                Ok(success) => {
                    let _ = sender.as_ref().unwrap().send((playerid, callback, success, optional_args));
                }
                Err(err) => {
                    error!("{} => {:?}", callback, err);
                }
            }
        });

        Ok(true)
    }
}

struct SampArgon2 {
    hashes: LinkedList<String>,
    pool: ThreadPool,
    hash_sender: Option<Sender<HashParams>>,
    hash_receiver: Option<Receiver<HashParams>>,
    verify_sender: Option<Sender<VerifyParams>>,
    verify_receiver: Option<Receiver<VerifyParams>>,
    amx_list: Vec<AmxIdent>
}

impl SampPlugin for SampArgon2 {
    fn on_load(&mut self) {
        info!("Plugin v0.1.0 loaded");
        let (verify_sender, verify_receiver) = channel();
        self.verify_sender = Some(verify_sender);
        self.verify_receiver = Some(verify_receiver);

        let (hash_sender, hash_receiver) = channel();
        self.hash_sender = Some(hash_sender);
        self.hash_receiver = Some(hash_receiver);
    }

    fn on_amx_load(&mut self, amx: &Amx) {
        self.amx_list.push(amx.ident());
    }

    fn on_unload(&mut self) {
        info!("Plugin v0.1.0 unloaded");
    }

    fn on_amx_unload(&mut self, amx: &Amx) {
        let raw = amx.ident();
        let index = self.amx_list.iter().position(|x| *x == raw).unwrap();
        self.amx_list.remove(index);
    }

    fn process_tick(&mut self) {
        for (playerid, callback, hashed, optional_args) in
            self.hash_receiver.as_ref().unwrap().try_iter()
        {
            let mut executed = false;
            self.hashes.push_front(hashed);

            for amx in &self.amx_list {
                if let Some(amx) = samp::amx::get(*amx) {
                    let allocator = amx.allocator();

                    for param in optional_args.iter().rev() {
                        match param {
                            ArgumentTypes::Primitive(x) => {
                                if amx.push(x).is_err() {
                                    error!("*Cannot execute callback {:?}", callback);
                                }
                            }
                            ArgumentTypes::String(data) => {
                                let buf = allocator.allot_buffer(data.len() + 1).unwrap();
                                let amx_str = unsafe { AmxString::new(buf, data) };
                                if amx.push(amx_str).is_err() {
                                    error!("*Cannot execute callback {:?}", callback);
                                }
                            }
                        }
                    }
                    if amx.push(playerid).is_err() {
                        error!("*Cannot execute callback {:?}", callback);
                    }
                    if let Ok(index) = amx.find_public(&callback) {
                        if amx.exec(index).is_ok() {
                            executed = true;
                            break;
                        }
                    }
                }
            }
            if !executed {
                error!("*Cannot execute callback {:?}", callback);
            }
        }

        for (playerid, callback, success, optional_args) in
            self.verify_receiver.as_ref().unwrap().try_iter()
        {
            let mut executed = false;
            for amx in &self.amx_list {
                if let Some(amx) = samp::amx::get(*amx) {
                    let allocator = amx.allocator();

                    for param in optional_args.iter().rev() {
                        match param {
                            ArgumentTypes::Primitive(x) => {
                                if amx.push(x).is_err() {
                                    error!("*Cannot execute callback {:?}", callback);
                                }
                            }
                            ArgumentTypes::String(data) => {
                                let buf = allocator.allot_buffer(data.len() + 1).unwrap();
                                let amx_str = unsafe { AmxString::new(buf, data) };
                                if amx.push(amx_str).is_err() {
                                    error!("*Cannot execute callback {:?}", callback);
                                }
                            }
                        }
                    }
                    if amx.push(success).is_err() {
                        error!("*Cannot execute callback {:?}", callback);
                    }
                    if amx.push(playerid).is_err() {
                        error!("*Cannot execute callback {:?}", callback);
                    }
                    if let Ok(index) = amx.find_public(&callback) {
                        if amx.exec(index).is_ok() {
                            executed = true;
                            break;
                        }
                    }
                }
            }
            if !executed {
                error!("*Cannot execute callback {:?}", callback);
            }
            if !executed {
                error!("*Cannot execute callback {:?}", callback);
            }
        }

        self.hashes.clear();
    }
}
