use std::collections::{HashMap, HashSet};
use std::time::Instant;

use ed25519_dalek::PublicKey as Ed25519PublicKey;
use num_bigint::BigUint;
use nym_sdk::mixnet;
use nym_sdk::mixnet::{MixPacket, Recipient, ReconstructedMessage};
use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use tracing::{debug, info, warn};

use crate::crypto::{
    generate_blinding_factor_y, generate_keypair, generate_message_a, generate_message_b,
    random_bigint, sign, verify, PuddingX25519PrivateKey, PuddingX25519PublicKey,
};
use crate::keyblinding::{blind_pubkey, convert_x25519_to_ed25519_private};
use crate::messages::Message;
use crate::orchestration::{AddressBook, GlobalConfiguration};
use crate::utils::create_new_mixnet_client;
use crate::Nonce;

/// The registering user struct holds the information about the users that are in the process of registration.
#[derive(Clone)]
pub struct RegisteredUser {
    pub delta: Recipient,
    pub signbit: u8,
    pub ed25519_pubkey: Ed25519PublicKey,
    pub x25519_pubkey: PuddingX25519PublicKey,
}

/// The registering user struct holds the information about the users that are in the process of registration.
#[derive(Clone)]
pub struct RegisteringUser {
    delta: Recipient,
    signbit: u8,
    ed25519_pubkey: Ed25519PublicKey,
    x25519_pubkey: PuddingX25519PublicKey,
    challenge: Nonce,
    nonce: BigUint,
}

pub(crate) struct DiscoveryServer {
    client: mixnet::MixnetClient,
    pub name: String,
    pub user_registry: HashMap<String, RegisteredUser>,
    // Every discovery node keeps track of registration requests that are still being processed
    ongoing_registrations: HashMap<BigUint, RegisteringUser>,
    // The d_auth uses this to keep track of challenge values from others for user registration
    collected_challenges: HashMap<BigUint, Vec<Nonce>>,
    // For keeping track of the nonce values that have already been received in lookup requests
    used_nonces: HashSet<Nonce>,
    // k value from the paper, a shared secret that all discovery nodes know and use for deterministic SURB generation
    shared_secret: Nonce,
    // Signing keys
    signing_key: SigningKey,
    // To keep track of the users you have sent a dkim request for
    dkim_started: HashSet<BigUint>,
    pub verify_key: VerifyingKey,
}

impl DiscoveryServer {
    pub async fn new(name: String, shared_secret: Nonce) -> DiscoveryServer {
        let client = create_new_mixnet_client().await;
        info!(
            "Created discovery server: {} ({})",
            name,
            client.nym_address()
        );

        let (signing_key, verify_key) = generate_keypair();

        DiscoveryServer {
            client,
            name,
            user_registry: HashMap::new(),
            ongoing_registrations: HashMap::new(),
            collected_challenges: HashMap::new(),
            used_nonces: HashSet::new(),
            dkim_started: HashSet::new(),
            shared_secret,
            signing_key,
            verify_key,
        }
    }

    pub fn get_address(&self) -> Recipient {
        return *self.client.nym_address();
    }

    pub async fn run(&mut self, address_book: AddressBook, global_config: GlobalConfiguration) {
        info!("{} is running", self.name);
        loop {
            if let Some(messages) = self.client.wait_for_messages().await {
                for msg in messages {
                    self.handle_message(msg, &address_book, &global_config)
                        .await;
                }
            };
        }
    }

    async fn handle_message(
        &mut self,
        msg: ReconstructedMessage,
        address_book: &AddressBook,
        global_config: &GlobalConfiguration,
    ) {
        let content = String::from_utf8_lossy(&msg.message);
        let content_size = content.len();

        let message: Message = serde_json::from_str(&content).expect("Invalid message");
        debug!("{} received: {} ({content_size} bytes)", self.name, message);

        match message {
            Message::ClientRegister {
                send_time: _,
                id,
                delta,
                signbit,
                d_auth,
                ed25519_pubkey,
                x25519_pubkey,
                nonce,
            } => {
                debug!("{} received registration message from {}", self.name, id);
                let ed_public = Ed25519PublicKey::from_bytes(&ed25519_pubkey).unwrap();
                let x_public = PuddingX25519PublicKey::from(x25519_pubkey);
                self.handle_registration(
                    id,
                    delta,
                    signbit,
                    d_auth,
                    address_book,
                    ed_public,
                    x_public,
                    nonce,
                )
                .await;
            }
            Message::RegistrationChallenge {
                send_time: _,
                id,
                challenge,
                nonce,
            } => {
                debug!("{} received challenge message from {}", self.name, id);

                self.handle_challenge(id, challenge, address_book, global_config, nonce)
                    .await;
            }
            Message::DkimRequest { .. } => {
                warn!("Server should not receive DkimRequest messages");
            }
            Message::LookupRequest {
                send_time: _,
                id,
                nonce,
            } => {
                // TODO: Refactor as separate function process_lookup_request()
                self.handle_lookup(msg, address_book, &id, &nonce).await;
            }
            Message::LookupResponse { .. } => {
                warn!("Server should not receive LookupResponse messages");
            }
            Message::LookupNotif { .. } => {
                warn!("Server should not receive LookupNotif messages");
            }
            Message::DkimResponse {
                unsigned_message,
                sender,
                send_time: _,
                signed_message,
                nonce,
            } => {
                debug!("{} received DKIM response", self.name);

                self.handle_dkim_response(
                    address_book,
                    &unsigned_message,
                    sender,
                    &signed_message,
                    nonce,
                )
                .await;
            }
            Message::RegistrationConfirm { .. } => {
                warn!("Server should not receive RegistrationConfirm messages");
            }
            Message::MInit { .. } => {
                warn!("Server should not receive MInit messages");
            }
            Message::WrappedMInit { m_init } => {
                // Reflect the m_init message to the anonymous searchee
                #[allow(deprecated)]
                let raw_packets: Vec<Vec<u8>> = m_init
                    .into_iter()
                    .map(|x| base64::decode(x).unwrap())
                    .collect();
                let packets = raw_packets
                    .into_iter()
                    .map(|x| MixPacket::try_from_bytes(x.as_slice()).unwrap())
                    .collect();

                self.client.send_packets(packets).await;
            }
            Message::AddFriend { .. } => {
                warn!("Server should not receive AddFriend messages");
            }
        }
    }

    async fn handle_registration(
        &mut self,
        id: String,
        delta: String,
        signbit: u8,
        d_auth: String,
        address_book: &AddressBook,
        ed25519_pubkey: Ed25519PublicKey,
        x25519_pubkey: PuddingX25519PublicKey,
        nonce: BigUint,
    ) {
        // Exit if the user's request is already being processed
        if self.ongoing_registrations.contains_key(&nonce) {
            debug!(
                "{} is already processing {}'s registration request, dropping this one",
                self.name, id
            );
            return;
        }

        // Generate a random challenge
        let challenge = random_bigint();

        let deserialized_delta: Recipient = delta.parse().unwrap();

        // Check if the user is already registered to this server
        if self.user_registry.contains_key(&id) {
            // If you want to allow users to register only once, you can uncomment this bit and put the next user_info assigment into an else block
            // That would be actually how the protocol works, but we're not doing this check in the data collection, since we are interested in
            // collecting as many registration requests as possible from a limited number of users.

            // user_info = RegisteringUser {
            //     id: id.clone(),
            //     challenge: challenge.clone(),
            //     delta: deserialized_delta.clone(),
            //     signbit,
            //     status: RegistrationStatus::Invalid,
            //     ed25519_pubkey,
            //     nonce: nonce.clone(),
            // };
            debug!("{} already has user {} in its registry", self.name, id)
        }
        let user_info = RegisteringUser {
            challenge: challenge.clone(),
            delta: deserialized_delta,
            signbit,
            ed25519_pubkey,
            x25519_pubkey,
            nonce: nonce.clone(),
        };
        debug!("{} starting registration for user {}", self.name, id);

        // Keep track of the information about the user's request
        self.ongoing_registrations.insert(nonce.clone(), user_info);

        // If you're not the d_auth, send your challenge to the d_auth
        if d_auth != self.name {
            debug!("{} sending challenge to {} for {}", self.name, d_auth, id);

            let challenge_message = Message::RegistrationChallenge {
                send_time: Instant::now(),
                id,
                challenge: challenge.clone(),
                nonce: nonce.clone(),
            };

            let d_auth_address = address_book.get_address(&d_auth);
            self.client
                .send_str(
                    d_auth_address,
                    &serde_json::to_string(&challenge_message).unwrap(),
                )
                .await;
        } else {
            self.collected_challenges
                .entry(nonce.clone())
                .or_default()
                .push(challenge);
        }
    }

    // ..........................................
    // REGISTER subprotocol
    // ..........................................

    // The d_auth processes the challenges as they arrive
    async fn handle_challenge(
        &mut self,
        id: String,
        challenge: Nonce,
        address_book: &AddressBook,
        global_config: &GlobalConfiguration,
        nonce: BigUint,
    ) {
        // Get reference to the existing challenge vector for the id, or a new vector
        self.collected_challenges
            .entry(nonce.clone())
            .or_default()
            .push(challenge);

        debug!(
            "Received {} challenges for {} so far",
            self.collected_challenges.get(&nonce).unwrap().len(),
            id
        );

        let f = global_config.f;

        if self.collected_challenges.get(&nonce).unwrap().len() >= (2 * f + 1).try_into().unwrap() {
            debug!("Received challenges from at least 2f nodes for {}", id);

            // Put all challenge values in a string, each one separated by a space
            let mut challenges_string = self
                .collected_challenges
                .get(&nonce)
                .unwrap()
                .iter()
                .map(|num| num.to_string())
                .collect::<Vec<String>>()
                .join(" ");

            // Append the user's ID to the beginning to this for identification + your own challenge
            challenges_string = format!("{} {}", id, challenges_string);

            // If you haven't already sent a DKIM request, send one
            if !self.dkim_started.contains(&nonce) {
                self.dkim_started.insert(nonce.clone());

                // Send this string to the DKIM service for signing
                let dkim_request = Message::DkimRequest {
                    send_time: Instant::now(),
                    message: challenges_string,
                    nonce: nonce.clone(),
                };

                let dkim_address = address_book.get_address(&address_book.dkim_name);

                self.client
                    .send_str(dkim_address, &serde_json::to_string(&dkim_request).unwrap())
                    .await;
            }
        }
    }

    async fn handle_dkim_response(
        &mut self,
        address_book: &AddressBook,
        unsigned_message: &String,
        sender: String,
        signed_message: &String,
        nonce: BigUint,
    ) {
        // If you've received this message from the DKIM service, you're the d_auth, send it to others.
        if sender == address_book.dkim_name {
            debug!("{} relaying the DKIM response to others", self.name);
            let relayed_dkim_message = Message::DkimResponse {
                sender: self.name.clone(),
                send_time: Instant::now(),
                unsigned_message: unsigned_message.clone(),
                signed_message: signed_message.clone(),
                nonce: nonce.clone(),
            };

            for server in address_book.server_names.iter() {
                // Relay to every server except yourself
                if server != self.name.as_str() {
                    let server_address = address_book.get_address(server);
                    self.client
                        .send_str(
                            server_address,
                            &serde_json::to_string(&relayed_dkim_message).unwrap(),
                        )
                        .await;
                }
            }
        }

        let message = unsigned_message;

        let message_vec: Vec<_> = message.split_whitespace().collect();
        let user_id = message_vec[0];

        if self.ongoing_registrations.contains_key(&nonce) {
            // Verify the DKIM signature
            let verifying_key = address_book.dkim_verify_key.unwrap();
            if !verify(&verifying_key, message, signed_message) {
                warn!(
                    "Registration of {} failed at {}: DKIM signature failed",
                    user_id, self.name
                );

                // We give up! But that should be no reason to not accept future registrations
                self.ongoing_registrations.remove(&nonce);

                return;
            }

            // Check if your challenge is included
            let challenge = self
                .ongoing_registrations
                .get(&nonce)
                .unwrap()
                .challenge
                .to_string();

            let challenge_str: &str = challenge.as_str();

            if !message_vec.contains(&challenge_str) {
                warn!(
                    "Registration of {} failed at {}: couldn't find my own challenge in the email",
                    user_id, self.name
                );

                // We give up! But that should be no reason to not accept future registrations
                // This might happen if our challenge got to `d_auth` late and was not included, since
                // it already had 2*f received previously
                self.ongoing_registrations.remove(&nonce);

                return;
            }

            debug!("{} calling complete_registration", self.name);
            self.complete_registration(user_id.to_string(), nonce.clone(), address_book)
                .await;
        }
    }

    async fn complete_registration(
        &mut self,
        user_id: String,
        nonce: BigUint,
        address_book: &AddressBook,
    ) {
        // Add the user to your user registry
        let registering_user = self.ongoing_registrations.get(&nonce).unwrap();
        let registered_user = RegisteredUser {
            delta: registering_user.delta,
            signbit: registering_user.signbit,
            ed25519_pubkey: registering_user.ed25519_pubkey,
            x25519_pubkey: registering_user.x25519_pubkey,
        };
        self.user_registry.insert(user_id.clone(), registered_user);

        debug!("{} successfully registered {}", self.name, user_id);

        // Send confirmation message to the userg
        let registration_confirm = Message::RegistrationConfirm {
            send_time: Instant::now(),
            sender: self.name.clone(),
            nonce: registering_user.nonce.clone(),
        };

        let user_address = address_book.get_address(&user_id);

        // This is no longer an on-going registration
        self.ongoing_registrations.remove(&nonce);

        self.client
            .send_str(
                user_address,
                &serde_json::to_string(&registration_confirm).unwrap(),
            )
            .await;
    }

    // ..........................................
    // LOOKUP subprotocol
    // ..........................................

    async fn handle_lookup(
        &mut self,
        msg: ReconstructedMessage,
        address_book: &AddressBook,
        id: &String,
        nonce: &BigUint,
    ) {
        // Don't process if you saw the nonce before
        if self.used_nonces.contains(nonce) {
            debug!(
                "Nonce reuse: {}, dropping the lookup request for ID {}",
                nonce, id
            );
            return;
        }

        self.used_nonces.insert(nonce.clone());
        let (bpk, x_bpk, sig_a, sig_b, y, surbs) =
            self.process_lookup(id.clone(), nonce, address_book).await;
        // Send (nonce, surb, bpk, sigA) to searcher
        let lookup_response = Message::LookupResponse {
            send_time: Instant::now(),
            sender: self.name.clone(),
            nonce: nonce.clone(),
            bpk: bpk.to_bytes(),
            x_bpk: x_bpk.0.to_bytes(),
            sig_a,
            surbs,
        };
        self.client
            .send_str_reply(
                msg.sender_tag.unwrap(),
                &serde_json::to_string(&lookup_response).unwrap(),
            )
            .await;

        // If ID is registered, send (nonce, y, sig_B) to id
        if let Some(_s) = &sig_b {
            let lookup_notif = Message::LookupNotif {
                send_time: Instant::now(),
                sender: self.name.clone(),
                nonce: nonce.clone(),
                y,
                sig_b: sig_b.clone().unwrap(),
            };

            let searchee_address = self.user_registry.get(id).unwrap().delta;
            self.client
                .send_str(
                    searchee_address,
                    &serde_json::to_string(&lookup_notif).unwrap(),
                )
                .await;
        }
    }

    async fn process_lookup(
        &mut self,
        id: String,
        nonce: &Nonce,
        address_book: &AddressBook,
    ) -> (
        Ed25519PublicKey,
        PuddingX25519PublicKey,
        String,
        Option<String>,
        [u8; 32],
        Vec<String>,
    ) {
        let blinded_pubkey;
        let blinded_x_pubkey;
        let surbs;
        let mut sig_b = None;

        // KDF(nonce ∥ id ∥ k)
        let seed = Sha512::new()
            .chain_update(nonce.to_bytes_be())
            .chain_update(id.as_bytes())
            .chain_update(self.shared_secret.to_bytes_be()) // shared_secret is k from the paper
            .finalize();

        // Generate a random y value from the seed you have created above
        let y = generate_blinding_factor_y(seed.as_slice().try_into().unwrap());

        // Search for id in your database
        if self.user_registry.contains_key(&id) {
            debug!(
                "{} is registered at {}, responding with real SURB",
                id, self.name
            );
            // Generate SURB for the real delta of the id
            surbs = self
                .client
                .create_surbs(
                    &self.user_registry.get(&id).unwrap().delta,
                    nonce.to_bytes_be(),
                    10,
                )
                .await
                .unwrap();

            // Convert the registered x25519 public key under id to ed25519 key
            let user_entry = self.user_registry.get(&id).unwrap();

            // Use the y value to blind the user's public key. bpk = (g^x)^y, where g^x is the user's public key
            blinded_pubkey = blind_pubkey(&user_entry.ed25519_pubkey, y).unwrap();

            let x_pubkey = &user_entry.x25519_pubkey;
            blinded_x_pubkey = x_pubkey.blind(y);

            // If id is registered, compute a signature sig_B = Sign_sk(nonce ∥ y)
            let message_b = generate_message_b(nonce.clone(), y);
            sig_b = Some(sign(&self.signing_key, &message_b));
        } else {
            debug!(
                "{} is not registered at {}, responding with fake SURB",
                id, self.name
            );

            // Generate SURB for the fake delta
            surbs = self
                .client
                .create_surbs(&address_book.fake_delta.unwrap(), nonce.to_bytes_be(), 10)
                .await
                .unwrap();

            // If id is not registered, compute a fake blinded key bpk = g^y instead
            // Convert y value to StaticSecret to make it compatible for calculating g^y
            let y_into_static_secret = x25519_dalek::StaticSecret::from(y);
            // Calculating g^y is essentially generating a public key from y
            let (fake_blinded_kp, _) =
                convert_x25519_to_ed25519_private(&y_into_static_secret).unwrap();
            blinded_pubkey = fake_blinded_kp.public;
            let blinded_x_privkey = PuddingX25519PrivateKey::from(y_into_static_secret);
            blinded_x_pubkey = blinded_x_privkey.derive_public_key();
        }

        let serialized_surbs: Vec<String> =
            surbs.into_iter().map(|x| x.to_base58_string()).collect();

        // sig_A = Sign_sk(nonce ∥ surbs ∥ bpk)
        let message_a =
            generate_message_a(nonce.clone(), serialized_surbs.clone(), &blinded_pubkey);
        let sig_a = sign(&self.signing_key, &message_a);

        // Convert sig_b to Option<String> using Option::map
        let sig_b_option = sig_b.map(Some).unwrap_or(None);

        (
            blinded_pubkey,
            blinded_x_pubkey,
            sig_a,
            sig_b_option,
            y,
            serialized_surbs,
        )
    }
}
