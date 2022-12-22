use crate::celestia::{CelestiaClient, DataAvailable};
use crate::create_namespace;
use crate::redis_client::RedisClient;
use anyhow::anyhow;
use futures::future::err;
use reqwest::Error;
use serde::Deserialize;
use serde_json::Value;
use zksync_config::envy_load;
use zksync_types::block::Block;

/// Storage client is the data availability chain(DAC) interaction point.
/// It holds down the connection to the DAC
/// and provide methods to obtain different storage schemas.
#[derive(Debug, Clone)]
pub struct DACClient {
    celestia: CelestiaClient,
    redis: RedisClient,
    namespace: String,
}

impl DACClient {
    pub fn default() -> Self {
        let celestia = CelestiaClient::new();
        let redis = RedisClient::default();
        let namespace = create_namespace();
        Self {
            celestia,
            redis,
            namespace,
        }
    }
    pub async fn get_data_available(&self, block_height: u64) -> Result<DataAvailable, Error> {
        //self.celestia.get_data_available(block_height).await
        Ok(DataAvailable::new())
    }
    pub async fn store_block(&self, block: &Block, gas_limit: u64) -> Result<(), anyhow::Error> {
        vlog::info!("Store block {:?} on the DAC.", block);
        match serde_json::to_string(block) {
            Ok(data) => {
                self.redis
                    .store_block_data(block.block_number.to_string(), data);
            }
            Err(err) => {
                return Err(anyhow!(err));
            }
        }
        /*
        let data_avaiable = self.celestia.get_data_available(300).await;
        println!("{:?}", &data_avaiable);
        //Todo: Need to encode block data instead of convert tu serde_json: This can reduce data size by 50%
        match serde_json::to_string(block) {
            Ok(data) => {
                let hex_encode = hex::encode(&data);
                let hex_decode = hex::decode(hex_encode.clone())
                    .map(|res| String::from_utf8(res).unwrap_or_default())
                    .unwrap();
                println!(
                    "Input length: {}. Decoded data length: {}; {:?}",
                    data.len(),
                    hex_decode.len(),
                    hex_decode
                );
                match self
                    .celestia
                    .submit_pfd(&self.namespace, &hex_encode, gas_limit)
                    .await
                {
                    Ok(res) => {
                        println!("Submit_pdf result: {:?}", res);
                    }
                    Err(err) => {
                        anyhow!(err);
                    }
                }
                Ok(())
            }
            Err(err) => Err(anyhow!(err)),
        }
         */
        Ok(())
    }
}
