use base64::engine::general_purpose::STANDARD;
use base64::{DecodeError, Engine};
use nym_sdk::mixnet::MixnetClient;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    STANDARD.encode(input)
}

const CONNECTION_RETRIES: u32 = 5;

pub async fn create_new_mixnet_client() -> MixnetClient {
    let mut maybe_client = None;
    for _ in 0..CONNECTION_RETRIES {
        match MixnetClient::connect_new().await {
            Ok(client) => {
                maybe_client = Some(client);
                break;
            }
            Err(err) => {
                debug!("Connecting client failed (might retry): {}", err);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
    return maybe_client.expect("Connecting client failed too many times. Giving up.");
}
