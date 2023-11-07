use std::collections::HashMap;

use nym_sdk::mixnet;
use nym_sdk::mixnet::Recipient;
use p256::ecdsa::VerifyingKey;

use crate::clients::UserClient;
use crate::crypto::{generate_keypair, random_bigint, PuddingX25519PublicKey};
use crate::dkim::DkimService;
use crate::servers::{DiscoveryServer, RegisteredUser};

#[derive(Clone, Debug, PartialEq)]
pub enum Scenario {
    /// Execute just the Registration protocol
    Register,

    /// Pre-register all users and execute LookUp with anonymous ContactInit and AddFriend
    LookupAnonymous,

    /// Pre-register all users and execute LookUp with the NON-anonymous ContactInit and AddFriend
    LookupIdentity,
}

/// The global configuration is used as an element in the address book, it holds the n and f values
#[derive(Clone)]
pub struct GlobalConfiguration {
    pub num_users: u32,
    /// a.k.a "n"
    pub num_servers: u32,
    pub f: u32,
    /// 2 * f
    pub threshold: u32,
    pub scenario: Scenario,
}

impl GlobalConfiguration {
    pub fn new(num_users: u32, num_servers: u32, scenario: Scenario) -> GlobalConfiguration {
        if (num_servers - 1) % 3 != 0 || num_servers - 1 == 0 {
            panic!("Number of servers should be a whole number that can be represented as 3f + 1.");
        }

        GlobalConfiguration {
            num_users,
            num_servers,
            f: (num_servers - 1) / 3,
            threshold: 2 * ((num_servers - 1) / 3) + 1,
            scenario,
        }
    }
}

/// The address book is created by the [World] for all clients to allow looking up addresses.
#[derive(Clone)]
pub struct AddressBook {
    pub user_names: Vec<String>,
    pub server_names: Vec<String>,
    pub dkim_name: String,
    pub dkim_verify_key: Option<VerifyingKey>,
    pub fake_delta: Option<Recipient>,
    pub server_verification_keys: HashMap<String, VerifyingKey>,
    mapping: HashMap<String, Recipient>,
}

impl AddressBook {
    pub fn get_address(&self, name: &String) -> Recipient {
        self.mapping[name]
    }
}

/// The [World] is an instantiation of the test configuration and controls the execution of the
/// clients and servers.
pub struct World {
    pub address_book: AddressBook,
    pub global_config: GlobalConfiguration,
}

impl World {
    pub fn new(global_config: GlobalConfiguration) -> World {
        let user_names = (0..global_config.num_users)
            .map(|x| format!("u{}", x))
            .collect();
        let server_names = (0..global_config.num_servers)
            .map(|x| format!("s{}", x))
            .collect();
        let dkim_name = String::from("dkim");

        let address_book = AddressBook {
            user_names,
            server_names,
            dkim_name,
            fake_delta: None,
            dkim_verify_key: None,
            server_verification_keys: HashMap::new(),
            mapping: HashMap::new(),
        };

        World {
            address_book,
            global_config,
        }
    }

    pub async fn run(&mut self) {
        // Create all clients and servers; this includes registration and connecting
        // to the gateways
        let mut clients = Vec::new();
        for name in &self.address_book.user_names {
            let client = UserClient::new(name.clone()).await;
            self.address_book
                .mapping
                .insert(name.clone(), client.get_address());
            clients.push(client);
        }

        // Generate a shared secret for the discovery nodes
        let shared_secret = random_bigint();

        let mut servers = Vec::new();
        for name in &self.address_book.server_names {
            let server = DiscoveryServer::new(name.clone(), shared_secret.clone()).await;
            self.address_book
                .mapping
                .insert(name.clone(), server.get_address());

            // Add server verification key to address book to enable access to clients.
            self.address_book
                .server_verification_keys
                .insert(server.name.clone(), server.verify_key);

            servers.push(server);
        }

        let (signing_key, verify_key) = generate_keypair();
        self.address_book.dkim_verify_key = Some(verify_key);

        let mut dkim = DkimService::new(signing_key).await;
        self.address_book
            .mapping
            .insert(self.address_book.dkim_name.clone(), dkim.get_address());

        // Set the fake delta to be the delta of a random client that we use temporarily
        let mut fake_client = mixnet::MixnetClient::connect_new().await.unwrap();
        self.address_book.fake_delta = Some(*fake_client.nym_address());
        fake_client.disconnect().await;

        // At this points all clients and servers are up (and have their addresses registered)

        // Start the respective run methods and join/wait on all those handles
        let mut handles = Vec::new();

        for mut server in servers {
            let address_book_clone = self.address_book.clone();
            let global_config_clone = self.global_config.clone();

            // Pre-register clients always unless we are in the REGISTER scenario
            if self.global_config.scenario != Scenario::Register {
                for client in &clients {
                    let registered_user = RegisteredUser {
                        delta: self.address_book.get_address(&client.name),
                        signbit: client.ed25519_keypair.signbit(),
                        ed25519_pubkey: client.ed25519_keypair.public,
                        x25519_pubkey: PuddingX25519PublicKey::from(
                            *client.x25519_public_key.as_bytes(),
                        ),
                    };
                    server
                        .user_registry
                        .insert(client.name.clone(), registered_user);
                }
            }
            let handle =
                tokio::spawn(
                    async move { server.run(address_book_clone, global_config_clone).await },
                );
            handles.push(handle);
        }

        for mut client in clients {
            let address_book_clone = self.address_book.clone();
            let global_config_clone = self.global_config.clone();
            let handle =
                tokio::spawn(
                    async move { client.run(address_book_clone, global_config_clone).await },
                );
            handles.push(handle);
        }

        let handle = tokio::spawn(async move { dkim.run().await });
        handles.push(handle);

        futures::future::join_all(handles).await;
    }
}
