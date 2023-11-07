extern crate core;

use num_bigint::BigUint;

mod clients;
mod crypto;
mod dkim;
mod keyblinding;
mod messages;
pub mod orchestration;
mod servers;
mod utils;

type Nonce = BigUint;
