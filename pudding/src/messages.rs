use std::fmt;
use std::time::Instant;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Message {
    ClientRegister {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        id: String,
        delta: String,
        signbit: u8,
        d_auth: String,
        ed25519_pubkey: [u8; 32],
        x25519_pubkey: [u8; 32],
        nonce: BigUint,
    },
    RegistrationChallenge {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        id: String,
        nonce: BigUint,
        challenge: BigUint,
    },
    DkimRequest {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        message: String,
        nonce: BigUint,
    },
    DkimResponse {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        sender: String,
        unsigned_message: String,
        signed_message: String,
        nonce: BigUint,
    },
    RegistrationConfirm {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        sender: String,
        nonce: BigUint,
    },
    LookupRequest {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        id: String,
        nonce: BigUint,
    },
    LookupResponse {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        sender: String,
        nonce: BigUint,
        bpk: [u8; 32],
        x_bpk: [u8; 32],
        sig_a: String,
        surbs: Vec<String>,
    },
    // Message that the discovery nodes send to searchee
    LookupNotif {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        sender: String,
        nonce: BigUint,
        y: [u8; 32],
        sig_b: String,
    },
    // TODO: WrappedMinit should have Minit Sphinx packet as a field.
    MInit {
        #[serde(with = "serde_millis")]
        send_time: Instant,
        enc_msg: String,
        nonce: BigUint,
        dh_pk: [u8; 32],
        // To allow Bob to anonymously respond to Alice
        searcher_surbs: Vec<String>,
    },
    WrappedMInit {
        // Discovery nodes will use this to reflect the message to Bob
        m_init: Vec<String>,
    },
    AddFriend {
        public_key: [u8; 32],
        // Only used in the first AddFriend message within a protocol run
        dh_pk: Option<[u8; 32]>,
        // If the user who initiated AddFriend by sending M_init wants to remain anonymous, they don't include their username in their AddFriend message
        sender: Option<String>,
        sign: String,
        nonce: BigUint,
        surbs: Option<Vec<String>>,
        // Needed to keep track of keys if lookup is called as part of AddFriend
        assoc_nonce: Option<BigUint>,
        mac: [u8; 32],
    },
}

#[derive(Serialize, Deserialize)]
pub enum MinitPayload {
    Anon { pk: [u8; 32] },
    NonAnon { id: String },
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Message::ClientRegister { .. } => {
                write!(f, "ClientRegister")
            }
            Message::RegistrationChallenge { .. } => {
                write!(f, "RegistrationChallenge")
            }
            Message::DkimRequest { .. } => {
                write!(f, "DkimRequest")
            }
            Message::DkimResponse { .. } => {
                write!(f, "DkimResponse")
            }
            Message::RegistrationConfirm { .. } => {
                write!(f, "RegistrationConfirm")
            }
            Message::LookupRequest { .. } => {
                write!(f, "LookupRequest")
            }
            Message::LookupResponse { .. } => {
                write!(f, "LookupResponse")
            }
            Message::LookupNotif { .. } => {
                write!(f, "LookupNotif")
            }
            Message::MInit { .. } => {
                write!(f, "MInit")
            }
            Message::WrappedMInit { .. } => {
                write!(f, "WrappedMInit")
            }
            Message::AddFriend { .. } => {
                write!(f, "AddFriend")
            }
        }
    }
}
