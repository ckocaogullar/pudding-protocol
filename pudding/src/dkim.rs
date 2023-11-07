use std::time::Instant;

use p256::ecdsa::SigningKey;
// requires 'getrandom' feature

use nym_sdk::mixnet;
use nym_sdk::mixnet::{Recipient, ReconstructedMessage};
use tracing::{debug, info, warn};

use crate::crypto;
use crate::messages::Message;
use crate::utils::create_new_mixnet_client;

pub(crate) struct DkimService {
    client: mixnet::MixnetClient,
    name: String,
    signing_key: SigningKey,
}

impl DkimService {
    pub async fn new(signing_key: SigningKey) -> DkimService {
        let client = create_new_mixnet_client().await;
        let name = String::from("dkim");
        info!("Created DKIM service: {} ({})", name, client.nym_address());
        DkimService {
            client,
            name,
            signing_key,
        }
    }

    pub fn get_address(&self) -> Recipient {
        return *self.client.nym_address();
    }

    pub async fn run(&mut self) {
        info!("{} is running", self.name);
        loop {
            if let Some(messages) = self.client.wait_for_messages().await {
                for msg in messages {
                    self.handle_message(msg).await;
                }
            };
        }
    }

    async fn handle_message(&mut self, msg: ReconstructedMessage) {
        let content = String::from_utf8_lossy(&msg.message);
        let content_size = content.len();

        let message: Message = serde_json::from_str(&content).expect("Invalid message");
        debug!("{} received: {} ({content_size} bytes)", self.name, message);
        match message {
            Message::DkimRequest {
                send_time: _,
                message,
                nonce,
            } => {
                let dkim_response = Message::DkimResponse {
                    sender: self.name.clone(),
                    send_time: Instant::now(),
                    unsigned_message: message.clone(),
                    signed_message: crypto::sign(&self.signing_key, &message),
                    nonce: nonce.clone(),
                };
                self.client
                    .send_str_reply(
                        msg.sender_tag.unwrap(),
                        &serde_json::to_string(&dkim_response).unwrap(),
                    )
                    .await;
            }
            Message::DkimResponse { .. } => {
                warn!("Dkim should not receive DkimResponse messages");
            }
            Message::ClientRegister { .. } => {
                warn!("Dkim should not receive ClientRegister messages");
            }
            Message::RegistrationChallenge { .. } => {
                warn!("Dkim should not receive RegistrationChallenge messages");
            }
            Message::RegistrationConfirm { .. } => {
                warn!("Dkim should not receive RegistrationConfirm messages");
            }
            Message::LookupRequest { .. } => {
                warn!("Dkim should not receive LookupRequest messages");
            }
            Message::LookupResponse { .. } => {
                warn!("Dkim should not receive LookupResponse messages");
            }
            Message::LookupNotif { .. } => {
                warn!("Dkim should not receive LookupNotif messages");
            }
            Message::MInit { .. } => {
                warn!("Dkim should not receive MInit messages");
            }
            Message::WrappedMInit { .. } => {
                warn!("Dkim should not receive WrappedMInit messages");
            }
            Message::AddFriend { .. } => {
                warn!("Server should not receive AddFriend messages");
            }
        }
    }
}
