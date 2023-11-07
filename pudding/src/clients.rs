use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
#[allow(deprecated)]
use base64::{decode, encode};
use bimap::BiMap;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use ed25519_dalek::{ExpandedSecretKey, Signature, Verifier};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use nym_sdk::mixnet::{MixnetClient, ReplySurb};
use nym_sdk::mixnet::{Recipient, ReconstructedMessage};
use rand::prelude::IteratorRandom;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::time::timeout;
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey as X25519PublicKey;
use x25519_dalek::StaticSecret;

use crate::crypto::{
    aes_decrypt, aes_encrypt, generate_blinding_factor_y, generate_message_a, generate_message_b,
    random_bigint, verify, PuddingX25519PrivateKey, PuddingX25519PublicKey,
};
use crate::keyblinding::{blind_keypair, ExpandedKeypair};
use crate::messages::{Message, MinitPayload};
use crate::orchestration::{AddressBook, GlobalConfiguration, Scenario};
use crate::utils::{base64_decode, base64_encode, create_new_mixnet_client};
use crate::Nonce;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub(crate) struct UserClient {
    client: MixnetClient,
    pub name: String,

    /// User keypair (public key from your Delta and the corresponding secret key) converted to ed25519 from x25519
    /// This conversion is necessary for key blinding
    pub ed25519_keypair: ExpandedKeypair,
    pub x25519_private_key: StaticSecret,
    pub x25519_public_key: X25519PublicKey,

    /// For registration bookkeeping
    registered_servers: Vec<String>,

    /// For keeping track of if a received registration response is for an uncompleted registration or not
    ongoing_registration_nonces: HashSet<BigUint>,

    /// For registration timekeeping
    register_start: Option<Instant>,
    register_end: Option<Instant>,

    /// For add friend timekeeping
    addfriend_times: HashMap<Nonce, Instant>,

    /// For keeping track of nonce - searchee ID mappings
    lookup_requests: BiMap<Nonce, String>,

    /// For keeping track of which discovery nodes have responded to your lookup requests with which LookupData
    /// HashMap<SearcheeID, HashMap<LookupData, Vec<ServerID>>>
    lookup_responses: HashMap<String, HashMap<LookupData, Vec<String>>>,

    /// For keeping track of lookup times
    lookup_times: HashMap<Nonce, Instant>,

    /// For keeping track of blinding keys from lookup notifications you receive as a searchee.
    /// HashMap<nonce, HashMap<blinding_key (y), Vec<ServerID>>
    lookup_notifs: HashMap<Nonce, HashMap<[u8; 32], Vec<String>>>,

    /// For storing the blinding factors that will allow you to authenticate those who searched you through AddFriend
    /// HashMap<nonce, blinding_factor>
    my_blinding_factors: HashMap<Nonce, [u8; 32]>,

    /// A hashmap for keeping track of the public key of the other user's (searcher's) public key,
    /// This is necessary as depending on the searcher providing her ID or not, you might need to run lookup
    /// HashMap<nonce, Option<public_key>>
    received_pubkeys: HashMap<Nonce, Option<[u8; 32]>>,

    /// A hashmap for keeping track of the DH ephemeral keys you generate for the AddFriend protocol
    /// HashMap<nonce, (dh_seckey, dh_pubkey)>
    my_dh_keys: HashMap<Nonce, (StaticSecret, X25519PublicKey)>,

    /// A hashmap for keeping track of the DH ephemeral public keys you receive during
    /// HashMap<nonce, dh_pubkey>
    received_dh_keys: HashMap<Nonce, X25519PublicKey>,

    /// For storing the MAC keys calculated in AddFriend to avoid repetition
    /// HashMap<nonce, MAC_key>
    addfriend_mackeys: HashMap<Nonce, [u8; 32]>,

    /// To prevent unneccessary processing of extra lookup responses
    lookup_finished: HashSet<Nonce>,

    /// To keep track of the nonce mappings between each Lookup called from AddFriend runs, and the nonce used in the corresponding AddFriend run
    /// BiMap<nonce from the caller (AddFriend), nonce from the callee (Lookup)>
    assoc_nonces: BiMap<Nonce, Nonce>,
}

/// The registering user struct holds the information about the users that are in the process of registration.
#[derive(Clone, Eq)]
pub struct LookupData {
    nonce: Nonce,
    bpk: Ed25519PublicKey,
    x_bpk: PuddingX25519PublicKey,
    surbs: Vec<String>,
}

// Implement PartialEq for LookupData to derive Eq
impl PartialEq for LookupData {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.bpk.as_bytes() == other.bpk.as_bytes()
            && self.x_bpk.0.as_bytes() == other.x_bpk.0.as_bytes()
            && self.surbs.len() == other.surbs.len() // Check if the vectors have the same length
            && self.surbs.iter().zip(&other.surbs).all(|(s1, s2)| s1 == s2)
    }
}

// Implement Hash for LookupData to use it as a HashMap key
impl Hash for LookupData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.nonce.hash(state);
        self.bpk.as_bytes().hash(state);
        self.x_bpk.0.as_bytes().hash(state);

        // Hash each element of the surb vector individually
        for s in &self.surbs {
            s.hash(state);
        }
    }
}

impl ExpandedKeypair {
    pub(crate) fn signbit(&self) -> u8 {
        return self.public.as_bytes()[31] >> 7;
    }
}

impl UserClient {
    pub async fn new(name: String) -> UserClient {
        let client = create_new_mixnet_client().await;
        info!("Created user: {} ({})", name, client.nym_address());

        let secrets = client.get_secrets();

        let ed25519_keypair = ExpandedKeypair {
            secret: ExpandedSecretKey::from(&secrets.identity_keypair.private_key().0),
            public: secrets.identity_keypair.public_key().0,
        };

        let x25519_private_key =
            StaticSecret::from(secrets.encryption_keypair.private_key().0.to_bytes());
        let x25519_public_key = secrets.encryption_keypair.public_key().0;

        UserClient {
            client,
            name,
            ed25519_keypair,
            x25519_private_key,
            x25519_public_key,
            registered_servers: Vec::new(),
            register_start: None,
            register_end: None,
            lookup_requests: BiMap::new(),
            lookup_responses: HashMap::new(),
            lookup_times: HashMap::new(),
            lookup_notifs: HashMap::new(),
            my_blinding_factors: HashMap::new(),
            received_pubkeys: HashMap::new(),
            my_dh_keys: HashMap::new(),
            received_dh_keys: HashMap::new(),
            addfriend_mackeys: HashMap::new(),
            addfriend_times: HashMap::new(),
            lookup_finished: HashSet::new(),
            assoc_nonces: BiMap::new(),
            ongoing_registration_nonces: HashSet::new(),
        }
    }

    pub fn get_address(&self) -> Recipient {
        return *self.client.nym_address();
    }

    pub async fn run(&mut self, address_book: AddressBook, global_config: GlobalConfiguration) {
        info!("{} is running", self.name);

        // Start a new protocol run for this client every `duration_between_actions` time period
        // but delay the first one by a random amount up to this period.
        let duration_between_actions = Duration::from_secs(30);
        let random_offset = duration_between_actions.mul_f32(thread_rng().gen_range(0.0..1.0));
        let mut next_action = Instant::now() + random_offset;

        loop {
            // trigger a new execution if we are past our schedule time
            if Instant::now() > next_action {
                match global_config.scenario {
                    Scenario::Register => {
                        info!("{} starts a new registration run", self.name);
                        self.start_register(&address_book).await;
                    }
                    Scenario::LookupAnonymous | Scenario::LookupIdentity => {
                        info!("{} starts a new lookup run", self.name);
                        self.start_lookup(&address_book).await;
                    }
                }
                next_action = Instant::now() + duration_between_actions;
            }

            // handle incoming messages
            // TODO: should be done more properly with the `select!` marco... we have a small risk to loose messages..
            let maybe_messages =
                timeout(Duration::from_secs(1), self.client.wait_for_messages()).await;
            if let Ok(Some(messages)) = maybe_messages {
                for msg in messages {
                    self.handle_message(msg, &address_book, &global_config)
                        .await;
                }
            }
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
            Message::ClientRegister { .. } => {
                warn!("User should not receive ClientRegister messages");
            }
            Message::RegistrationChallenge { .. } => {
                warn!("User should not receive RegistrationChallenge messages");
            }
            Message::DkimRequest { .. } => {
                warn!("User should not receive DkimRequest messages");
            }
            Message::DkimResponse { .. } => {
                warn!("User should not receive DkimResponse messages");
            }
            Message::LookupRequest { .. } => {
                warn!("User should not receive LookupRequest messages");
            }
            Message::LookupResponse {
                send_time: _,
                sender,
                nonce,
                bpk,
                x_bpk,
                sig_a,
                surbs,
            } => {
                self.handle_lookup_response(
                    address_book,
                    global_config,
                    sender,
                    nonce,
                    bpk,
                    x_bpk,
                    sig_a,
                    surbs,
                )
                .await;
            }
            Message::LookupNotif {
                send_time: _,
                sender,
                nonce,
                y,
                sig_b,
            } => {
                self.handle_lookup_notif(sender, nonce, y, sig_b, address_book, global_config)
                    .await;
            }
            Message::RegistrationConfirm {
                send_time: _,
                sender,
                nonce,
            } => {
                self.handle_registration_confirm(sender, global_config, nonce)
                    .await;
            }
            Message::MInit {
                send_time,
                enc_msg,
                nonce,
                dh_pk,
                searcher_surbs,
            } => {
                self.handle_minit(
                    address_book,
                    send_time,
                    enc_msg,
                    nonce,
                    dh_pk,
                    searcher_surbs,
                    global_config,
                )
                .await;
            }
            Message::WrappedMInit { .. } => {
                warn!("Client should not receive WrappedMInit messages");
            }
            Message::AddFriend {
                public_key,
                dh_pk,
                sender,
                sign,
                assoc_nonce,
                surbs,
                nonce,
                mac,
            } => {
                self.handle_add_friend(
                    public_key,
                    dh_pk,
                    sender,
                    sign,
                    assoc_nonce,
                    surbs,
                    &nonce,
                    mac,
                    global_config,
                )
                .await;
            }
        }
    }

    async fn handle_add_friend(
        &mut self,
        public_key: [u8; 32],
        dh_pk: Option<[u8; 32]>,
        sender: Option<String>,
        sign: String,
        assoc_nonce: Option<BigUint>,
        surbs: Option<Vec<String>>,
        nonce: &BigUint,
        mac: [u8; 32],
        global_config: &GlobalConfiguration,
    ) {
        // If the message includes a Diffie-Hellman public key, then this is the first AddFriend message of the protocol run
        if let Some(k) = dh_pk {
            self.received_dh_keys
                .insert(nonce.clone(), X25519PublicKey::from(k));
            self.received_pubkeys
                .insert(nonce.clone(), Some(public_key));
            let addfriend_msg = self
                .add_friend_message(nonce.clone(), false, assoc_nonce.clone(), global_config)
                .await;
            let deserialized_surbs: Vec<ReplySurb> = surbs
                .unwrap()
                .into_iter()
                .map(|x| ReplySurb::from_base58_string(x).unwrap())
                .collect();
            self.client
                .send_str_with_surb(deserialized_surbs, &addfriend_msg)
                .await;
            // Check the validity of the MAC and the signature
            let check = self
                .add_friend_checks(
                    sender.clone(),
                    nonce.clone(),
                    sign.clone(),
                    mac,
                    assoc_nonce.clone(),
                )
                .await;
            assert!(check.is_ok());
            debug!("{} : {} add_friend_check passed!", self.name, nonce);
        } else {
            // Check the validity of the MAC and the signature
            let check = self
                .add_friend_checks(sender.clone(), nonce.clone(), sign.clone(), mac, None)
                .await;
            assert!(check.is_ok());
            debug!("{} : {} add_friend_check passed!", self.name, nonce);
            let now = Instant::now();
            let start = *self.addfriend_times.get(nonce).unwrap();
            let rtt = now - start;

            info! {"ADDFRIEND {:?} {} {} : {}", sender, self.name, nonce, rtt.as_millis()}
        }
    }

    async fn handle_minit(
        &mut self,
        address_book: &AddressBook,
        send_time: Instant,
        enc_msg: String,
        nonce: BigUint,
        dh_pk: [u8; 32],
        searcher_surbs: Vec<String>,
        global_config: &GlobalConfiguration,
    ) {
        let mut sender: Option<String> = None;
        let mut sign_pk: Option<[u8; 32]> = None;

        self.addfriend_times.insert(nonce.clone(), send_time);

        // Create a symmetric key from your DH private key and the other user's bpk
        let y = self.my_blinding_factors.get(&nonce).unwrap();
        let _blinded_keypair = blind_keypair(&self.ed25519_keypair, *y).unwrap();

        // Convert your own private pk into PuddingX25519PrivateKey format
        let x_sk = StaticSecret::from(self.x25519_private_key.to_bytes());
        let pudding_blinded_sk = PuddingX25519PrivateKey::from(x_sk).blind(*y);

        // Convert the other's DH public key into PuddingX25519PublicKey format
        let pudding_dh_pk: PuddingX25519PublicKey = PuddingX25519PublicKey::from(dh_pk);
        let key = pudding_blinded_sk.dh(&pudding_dh_pk);

        let bytes = base64_decode(enc_msg).unwrap();

        let recovered = aes_decrypt(&key, bytes);

        // Figure out if the user sent a public key or their username

        let message: MinitPayload =
            serde_json::from_slice(recovered.as_slice()).expect("Invalid message");

        match message {
            MinitPayload::Anon { pk } => {
                sign_pk = Some(pk);
            }
            MinitPayload::NonAnon { id } => {
                sender = Some(id);
            }
        }

        // Save the DH public key you've received
        self.received_dh_keys
            .insert(nonce.clone(), X25519PublicKey::from(dh_pk));

        // Generate a DH keypair and save it
        let dummy_seed = [58u8; 32];
        let rng = ChaCha20Rng::from_seed(dummy_seed);

        let dh_secret = StaticSecret::new(rng);
        let dh_public = X25519PublicKey::from(&dh_secret);
        self.my_dh_keys
            .insert(nonce.clone(), (dh_secret, dh_public));

        // If the searcher didn't provide their ID but instead a fresh public key, set the public key you'll use in add_friend to that
        // Otherwise, initiate lookup for the searcher's ID to learn their blinded public key (bpk) instead
        if let Some(pk_sender) = sign_pk {
            debug!(
                "{} received add_friend request from an anonymous searcher",
                self.name
            );

            self.received_pubkeys.insert(nonce.clone(), Some(pk_sender));
            let addfriend_msg = self
                .add_friend_message(nonce.clone(), true, None, global_config)
                .await;
            let deserialized_surbs: Vec<ReplySurb> = searcher_surbs
                .into_iter()
                .map(|x| ReplySurb::from_base58_string(x).unwrap())
                .collect();
            self.client
                .send_str_with_surb(deserialized_surbs, &addfriend_msg)
                .await;
        } else {
            let sender_name = sender.unwrap();
            debug!(
                "{} received add_friend request from {}",
                self.name, sender_name
            );
            self.received_pubkeys.insert(nonce.clone(), None);
            // If the user included their name, run lookup to learn their bpk
            self.lookup(sender_name.clone(), address_book, Some(nonce.clone()))
                .await;
        }
    }

    async fn start_register(&mut self, address_book: &AddressBook) {
        debug!("Registration called");
        self.register_start = Some(Instant::now());
        // choose random d_auth server
        let d_auth = address_book
            .server_names
            .choose(&mut thread_rng())
            .unwrap()
            .clone();

        let recipient = self.get_address();
        let delta = recipient.to_string();

        // Generate a random nonce
        let nonce = random_bigint();

        let registration_message = Message::ClientRegister {
            send_time: Instant::now(),
            id: self.name.clone(),
            signbit: self.ed25519_keypair.signbit(),
            delta,
            d_auth,
            ed25519_pubkey: self.ed25519_keypair.public.to_bytes(),
            x25519_pubkey: self.x25519_public_key.to_bytes(),
            nonce: nonce.clone(),
        };

        // Keep track of this registration as an ongoing one
        self.ongoing_registration_nonces.insert(nonce.clone());

        for server in address_book.server_names.iter() {
            let server_address = address_book.get_address(server);
            self.client
                .send_str(
                    server_address,
                    &serde_json::to_string(&registration_message).unwrap(),
                )
                .await;
        }
    }

    async fn handle_registration_confirm(
        &mut self,
        sender: String,
        global_config: &GlobalConfiguration,
        nonce: BigUint,
    ) {
        self.registered_servers.push(sender);

        if self.registered_servers.len() >= global_config.threshold.try_into().unwrap()
            && self.ongoing_registration_nonces.contains(&nonce)
        {
            self.register_end = Some(Instant::now());
            let register_total = self.register_end.unwrap() - self.register_start.unwrap();
            info!("REGISTER {} : {}", self.name, register_total.as_millis());

            self.registered_servers.clear();
            self.ongoing_registration_nonces.remove(&nonce);
        }
    }

    /// Start Lookup for a random user who is not ourself
    async fn start_lookup(&mut self, address_book: &AddressBook) {
        let searchee_id: &String = address_book
            .user_names
            .iter()
            .filter(|name| name.as_str() != self.name)
            .choose(&mut thread_rng())
            .expect("No searchee candidate. Perhaps you only created a single user?");

        self.lookup(searchee_id.clone(), address_book, None).await;
    }

    async fn lookup(
        &mut self,
        searchee_id: String,
        address_book: &AddressBook,
        assoc_nonce: Option<Nonce>,
    ) {
        // Generate a random nonce
        let nonce = random_bigint();

        debug!(
            "{} starting lookup for {} : {}",
            self.name, searchee_id, nonce
        );

        let send_time = Instant::now();
        let lookup_request = Message::LookupRequest {
            send_time,
            id: searchee_id.clone(),
            nonce: nonce.clone(),
        };
        self.lookup_times.insert(nonce.clone(), send_time);
        self.lookup_requests
            .insert(nonce.clone(), searchee_id.clone());

        for server in address_book.server_names.iter() {
            let server_address = address_book.get_address(server);
            self.client
                .send_str(
                    server_address,
                    &serde_json::to_string(&lookup_request).unwrap(),
                )
                .await;
        }

        // If there is an associated nonce, i.e. this lookup has been called from AddFriend, record this nonce pairing
        if let Some(an) = assoc_nonce {
            self.assoc_nonces.insert(an.clone(), nonce.clone());
        }
    }

    async fn handle_lookup_response(
        &mut self,
        address_book: &AddressBook,
        global_config: &GlobalConfiguration,
        sender: String,
        nonce: BigUint,
        bpk: [u8; 32],
        x_bpk: [u8; 32],
        sig_a: String,
        surbs: Vec<String>,
    ) {
        // If lookup for this nonce has not already been completed
        if self.lookup_finished.contains(&nonce) {
            return;
        }
        // If the user called the lookup for the AddFriend protocol, proceed to send the AddFriend message returned by the handle_lookup_response
        let addfriend_msg = self
            .handle_lookup_response_inner(
                sender,
                nonce,
                bpk,
                x_bpk,
                sig_a,
                surbs.clone(),
                address_book,
                global_config,
            )
            .await;
        if let Some(af_msg) = addfriend_msg {
            let deserialized_surbs: Vec<ReplySurb> = surbs
                .into_iter()
                .map(|x| ReplySurb::from_base58_string(x).unwrap())
                .collect();
            self.client
                .send_str_with_surb(deserialized_surbs, &af_msg)
                .await;
        }
    }

    async fn handle_lookup_response_inner(
        &mut self,
        sender: String,
        nonce: Nonce,
        bpk: [u8; 32],
        x_bpk: [u8; 32],
        sig_a: String,
        surbs: Vec<String>,
        address_book: &AddressBook,
        global_config: &GlobalConfiguration,
    ) -> Option<String> {
        // Check that sig_a is valid
        let decoded_bpk = &Ed25519PublicKey::from_bytes(&bpk).unwrap();
        let decoded_x_bpk = &PuddingX25519PublicKey::from(x_bpk);
        let message_a = generate_message_a(nonce.clone(), surbs.clone(), decoded_bpk);
        if verify(
            address_book.server_verification_keys.get(&sender).unwrap(),
            &message_a,
            &sig_a,
        ) {
            let lookup_data = LookupData {
                bpk: *decoded_bpk,
                nonce: nonce.clone(),
                surbs: surbs.clone(),
                x_bpk: *decoded_x_bpk,
            };

            // TODO: since we use a BiMap this might throw if we have started looking up another
            // searchee in the mean time.
            let searchee_id = {
                let lookup_requests = &self.lookup_requests;
                lookup_requests.get_by_left(&nonce).unwrap().clone()
            };

            // If the LookupData has been received from another discovery node already, add the sender id to the vector
            // Otherwise, initialise a vector and add the id
            let inner_map = self
                .lookup_responses
                .entry(searchee_id.clone())
                .or_default();
            inner_map
                .entry(lookup_data)
                .or_default()
                .push(sender.clone());
            let min_servers = global_config.f + 1;

            // Check if you received at least f+1 of the same surb, nonce, and bpk values
            for server in self.lookup_responses.get(&searchee_id).unwrap().keys() {
                if self
                    .lookup_responses
                    .get(&searchee_id)
                    .and_then(|inner_map| inner_map.get(server))
                    .map_or(0, |vector| vector.len())
                    >= min_servers.try_into().unwrap()
                {
                    let lookup_start = self.lookup_times.get(&nonce);
                    let lookup_end = Instant::now();
                    let lookup_duration = lookup_end - *lookup_start.unwrap();
                    info!(
                        "LOOKUP {} {} : {}",
                        self.name,
                        searchee_id,
                        lookup_duration.as_millis()
                    );

                    self.lookup_finished.insert(nonce.clone());
                    // If this lookup request has been initiated from an AddFriend protocol run, add the bpk to the received_pubkeys and continue the addfriend run
                    if self.assoc_nonces.contains_right(&nonce) {
                        let assoc_nonce = self.assoc_nonces.get_by_right(&nonce).unwrap();
                        debug!(
                            "This lookup from {} to {} with nonce {} was initiated from Addfriend",
                            self.name, searchee_id, nonce
                        );
                        self.received_pubkeys.insert(assoc_nonce.clone(), Some(bpk));
                        let addfriend_msg = self
                            .add_friend_message(
                                assoc_nonce.clone(),
                                true,
                                Some(nonce.clone()),
                                global_config,
                            )
                            .await;
                        // return Some(serde_json::to_string(&addfriend_msg).unwrap())
                        return Some(addfriend_msg);
                    }
                }
            }
            // If lookup has finished, start ContactInit subprotocol
            if self.lookup_finished.contains(&nonce) {
                self.start_contact_init(
                    &searchee_id,
                    surbs.clone(),
                    bpk,
                    x_bpk,
                    address_book,
                    global_config,
                )
                .await;
            }
        }
        None
    }

    async fn handle_lookup_notif(
        &mut self,
        sender: String,
        nonce: Nonce,
        y: [u8; 32],
        sig_b: String,
        address_book: &AddressBook,
        global_config: &GlobalConfiguration,
    ) {
        // Check that sig_b is valid
        // Convert y from string to
        let message_b = generate_message_b(nonce.clone(), y);
        let min_servers = global_config.f + 1;

        if verify(
            address_book.server_verification_keys.get(&sender).unwrap(),
            &message_b,
            &sig_b,
        ) {
            let inner_map = self.lookup_notifs.entry(nonce.clone()).or_default();
            inner_map.entry(y).or_default().push(sender.clone());

            // Check if you received at least f+1 of the same nonce and y values
            for blinding_factor in self.lookup_notifs.get(&nonce).unwrap().keys() {
                if self
                    .lookup_notifs
                    .get(&nonce)
                    .and_then(|inner_map| inner_map.get(blinding_factor))
                    .map_or(0, |vector| vector.len())
                    >= min_servers.try_into().unwrap()
                {
                    self.my_blinding_factors
                        .insert(nonce.clone(), *blinding_factor);
                }
            }
        }
    }

    async fn start_contact_init(
        &mut self,
        searchee_id: &String,
        searchee_surbs: Vec<String>,
        _bpk: [u8; 32],
        x_bpk: [u8; 32],
        address_book: &AddressBook,
        global_config: &GlobalConfiguration,
    ) {
        let dummy_seed = [42u8; 32];
        let rng = ChaCha20Rng::from_seed(dummy_seed);

        // Change this value to toggle between anonymous and non-anonymous ContactInit
        let anonymous: bool = global_config.scenario == Scenario::LookupAnonymous;

        debug!(
            "{} starting ContactInit for {}; anonymous {}",
            self.name, searchee_id, anonymous
        );
        // choose random server
        let server = address_book
            .server_names
            .choose(&mut thread_rng())
            .unwrap()
            .clone();

        let server_address = address_book.get_address(&server);

        let rand_bigint = random_bigint();

        // Surbs to be used by Bob to reply to us (Alice)
        let many_surbs = self
            .client
            .create_surbs(&self.get_address(), rand_bigint.to_bytes_be(), 5)
            .await
            .unwrap();
        let many_serialized_surbs: Vec<String> = many_surbs
            .into_iter()
            .map(|x| x.to_base58_string())
            .collect();

        let nonce = self
            .lookup_requests
            .get_by_right(searchee_id)
            .unwrap()
            .clone();

        let _flag: [u8; 8];

        let msg = if anonymous {
            // Generate a blinding factor and blind your long-term public signing key with that
            // KDF(nonce)
            let seed = Sha512::new().chain_update(nonce.to_bytes_be()).finalize();

            // Generate a random y value from the seed you have created above
            let y = generate_blinding_factor_y(seed.as_slice().try_into().unwrap());

            // Save this blinding factor for future use
            self.my_blinding_factors.insert(nonce.clone(), y);

            let blinded_keypair = blind_keypair(&self.ed25519_keypair, y).unwrap();

            let anon_msg = MinitPayload::Anon {
                pk: blinded_keypair.public.to_bytes(),
            };

            serde_json::to_string(&anon_msg).unwrap()
        } else {
            let anon_msg = MinitPayload::NonAnon {
                id: self.name.clone(),
            };

            serde_json::to_string(&anon_msg).unwrap().clone()
        };

        // Generate a DH keypair and save it
        let dh_secret = StaticSecret::new(rng);
        let dh_public = X25519PublicKey::from(&dh_secret);
        self.my_dh_keys
            .insert(nonce.clone(), (dh_secret.clone(), dh_public));

        // Create a symmetric key from your DH private key and the other user's bpk.
        // We are using a separate bpk created solely for this purpose, which is a limitation of the implementation

        let dh_secret_as_pudding: PuddingX25519PrivateKey =
            PuddingX25519PrivateKey::from(dh_secret);
        let decoded_x_bpk: PuddingX25519PublicKey = PuddingX25519PublicKey::from(x_bpk);
        let key = dh_secret_as_pudding.dh(&decoded_x_bpk);

        // Encrypt block in-place
        let enc_msg = aes_encrypt(&key, msg.as_bytes().to_vec());

        // Form the minit
        let m_init = Message::MInit {
            send_time: Instant::now(),
            dh_pk: dh_public.to_bytes(),
            enc_msg: base64_encode(enc_msg),
            nonce: nonce.clone(),
            searcher_surbs: many_serialized_surbs,
        };

        let deserialised_searchee_surbs: Vec<ReplySurb> = searchee_surbs
            .into_iter()
            .map(|x| ReplySurb::from_base58_string(x).unwrap())
            .collect();

        // Alice then takes those SURBs and creates packets for Bob
        // (using a long message that requires fragmentation)
        let packets = self
            .client
            .create_mix_packet_with_surbs(
                &serde_json::to_string(&m_init).unwrap(),
                deserialised_searchee_surbs,
            )
            .await
            .unwrap();

        let raw_packets: Vec<Vec<u8>> = packets
            .into_iter()
            .map(|x| x.into_bytes().unwrap())
            .collect();

        #[allow(deprecated)]
        let serialized_packets: Vec<String> = raw_packets.into_iter().map(base64::encode).collect();

        let w_m_init = Message::WrappedMInit {
            m_init: serialized_packets,
        };

        self.client
            .send_str(server_address, &serde_json::to_string(&w_m_init).unwrap())
            .await;
    }

    async fn add_friend_checks(
        &mut self,
        sender: Option<String>,
        nonce: Nonce,
        sign: String,
        mac: [u8; 32],
        assoc_nonce: Option<Nonce>,
    ) -> Result<()> {
        let blinding_factor_nonce;
        if let Some(bfn) = assoc_nonce {
            blinding_factor_nonce = bfn;
        } else {
            blinding_factor_nonce = nonce.clone()
        }

        // Check that signature is valid

        // Blind your publix key with the associated blinding factor
        let y = self
            .my_blinding_factors
            .get(&blinding_factor_nonce)
            .unwrap();
        let blinded_keypair = blind_keypair(&self.ed25519_keypair, *y).unwrap();
        let _public_key = blinded_keypair.public.to_bytes();

        let other_pk_bytes = self.received_pubkeys.get(&nonce).unwrap().unwrap();
        let other_pk = Ed25519PublicKey::from_bytes(&other_pk_bytes).unwrap();

        // Use your and the other's DH public keys to create the message to be checked for signature
        let dh_pubkey = &self.my_dh_keys.get(&nonce).unwrap().1;
        let other_dh_pubkey = self.received_dh_keys.get(&nonce).unwrap();

        let msg: &[u8] = &[&other_dh_pubkey.to_bytes()[..], &dh_pubkey.to_bytes()[..]].concat();

        #[allow(deprecated)]
        let sign_slice: [u8; 64] = decode(sign)
            .expect("Invalid base64 string")
            .try_into()
            .unwrap();
        let sig_verified = other_pk.verify(msg, &Signature::from(sign_slice));

        // Get the MAC key K you've computed for this nonce before and verify the MAC
        let k = *self.addfriend_mackeys.get(&nonce).unwrap();

        let mut my_mac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");

        if let Some(s) = sender {
            let msg = &[s.as_bytes(), &other_pk_bytes[..]].concat();
            my_mac.update(msg);
        } else {
            my_mac.update(&other_pk_bytes);
        }

        let mac_verified = my_mac.clone().verify_slice(&mac[..]);

        // Perform the logical AND operation on the two values
        let logical_and_result = mac_verified.is_ok() && sig_verified.is_ok();

        if logical_and_result {
            Ok(())
        } else {
            Err(anyhow!("The logical AND is false"))
        }
    }

    async fn add_friend_message(
        &mut self,
        nonce: Nonce,
        first_message: bool,
        assoc_nonce: Option<Nonce>,
        global_config: &GlobalConfiguration,
    ) -> String {
        // If this is the second AddFriend message of the protocol run and there is an assoc_nonce provided,
        // This means that the other user has looked you up as part of AddFriend and you should use the assoc_nonce
        // to access the blinded key from their lookup's LookupNotifs
        let blinding_factor_nonce;
        if let Some(bfn) = assoc_nonce.clone() {
            if !first_message {
                blinding_factor_nonce = bfn;
            } else {
                blinding_factor_nonce = nonce.clone()
            }
        } else {
            blinding_factor_nonce = nonce.clone()
        }

        let remain_anonymous: bool = global_config.scenario == Scenario::LookupAnonymous;

        // Blind your keys for signing and verifying
        let y = *self
            .my_blinding_factors
            .get(&blinding_factor_nonce)
            .unwrap();
        let blinded_keypair = blind_keypair(&self.ed25519_keypair, y).unwrap();
        let public_key = blinded_keypair.public.to_bytes();
        let secret_key = &blinded_keypair.secret;

        // Use your blinded private key and the searcher's public key to compute DH shared secret
        let dh_seckey = &self.my_dh_keys.get(&nonce).unwrap().0;
        let dh_pubkey = &self.my_dh_keys.get(&nonce).unwrap().1;
        let received_dh_pubkey = self.received_dh_keys.get(&nonce).unwrap();
        let dh_shared_secret = dh_seckey.diffie_hellman(received_dh_pubkey);

        // Sign both your and the sender's DH public keys
        let concat_keys: &[u8] = &[
            &dh_pubkey.to_bytes()[..],
            &received_dh_pubkey.to_bytes()[..],
        ]
        .concat();
        let sign = secret_key.sign(
            concat_keys,
            &Ed25519PublicKey::from_bytes(&public_key).unwrap(),
        );

        // Derive a MAC key K from the shared secret and compute MAC_K(self.name)
        // KDF(dh_shared_secret)
        let k = Sha256::new()
            .chain_update(dh_shared_secret.to_bytes())
            .chain_update(b"MAC key")
            .finalize();

        // Store the MAC key if it hasn't been stored yet
        let k_slice: [u8; 32] = k.as_slice().try_into().expect("Wrong length");
        self.addfriend_mackeys
            .entry(nonce.clone())
            .or_insert(k_slice);

        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");

        let sender = if !remain_anonymous {
            let msg = &[self.name.as_bytes(), &public_key[..]].concat();
            mac.update(msg);
            Some(self.name.clone())
        } else {
            mac.update(&public_key);
            None
        };

        let mac_result = mac.finalize();

        let dh_pk;
        let surbs;

        // If this is the first add friend message, send over your DH public key
        if first_message {
            dh_pk = Some(dh_pubkey.to_bytes());
            let non_serialised_surbs = self
                .client
                .create_surbs(&self.get_address(), b"nonce".to_vec(), 1)
                .await
                .unwrap();
            let many_serialized_surbs: Vec<String> = non_serialised_surbs
                .into_iter()
                .map(|x| x.to_base58_string())
                .collect();
            surbs = Some(many_serialized_surbs);
        } else {
            dh_pk = None;
            surbs = None;
        }

        // Add a SURB for yourself

        // If there is an associated nonce, i.e. the user is not anonymous and you looked them up as part of AddFriend,
        // You should send the nonce value that you used in that lookup call. This will allow the user to find the correct
        // blinding factor, which they have received in LookupNotif messages from that lookup call.

        #[allow(deprecated)]
        let message = Message::AddFriend {
            public_key,
            sender,
            dh_pk,
            sign: encode(sign),
            surbs,
            assoc_nonce: assoc_nonce.clone(),
            nonce: nonce.clone(),
            mac: mac_result.into_bytes().try_into().expect("Invalid size"),
        };

        serde_json::to_string(&message).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recipient_serialization() {
        let user = UserClient::new(String::from("test")).await;
        let recipient = *user.client.nym_address();

        // Serialize the recipient to base58
        let serialized = recipient.to_string();

        // Deserialize the base58 back to an object
        let deserialized: Recipient = serialized.parse().unwrap();

        assert_eq!(deserialized, recipient);
    }
}
