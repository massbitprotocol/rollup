use reqwest::{Client, Error, Method, Request, RequestBuilder, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use zksync_config::envy_load;

#[derive(Debug, Deserialize, Clone)]
pub struct CelestiaConfig {
    rest_url: String,
}
impl CelestiaConfig {
    pub fn from_env() -> Self {
        envy_load!("celestia", "CELESTIA_")
    }
}
#[derive(Debug, Deserialize, Clone)]
pub struct DataAvailable {
    available: bool,
    probability_of_availability: String,
}

impl DataAvailable {
    pub fn new() -> DataAvailable {
        DataAvailable {
            available: false,
            probability_of_availability: "1".to_string(),
        }
    }
}
impl From<Value> for DataAvailable {
    fn from(val: Value) -> Self {
        DataAvailable {
            available: false,
            probability_of_availability: "".to_string(),
        }
    }
}
#[derive(Debug, Deserialize, Clone)]
pub struct MessageData {
    data: Vec<String>,
    height: u64,
}
#[derive(Debug, Clone)]
pub struct CelestiaClient {
    config: CelestiaConfig,
    inner: Client,
}
impl CelestiaClient {
    pub fn new() -> Self {
        let client = reqwest::Client::new();
        Self {
            config: CelestiaConfig::from_env(),
            inner: client,
        }
    }
    pub fn build_request(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}/{}", self.config.rest_url, path);
        self.inner.request(method, url)
    }
    pub fn post(&self, path: &str) -> RequestBuilder {
        let url = format!("{}/{}", self.config.rest_url, path);
        self.inner.post(url)
    }
    pub fn get(&self, path: &str) -> RequestBuilder {
        let url = format!("{}/{}", self.config.rest_url, path);
        self.inner.get(url)
    }
}

impl CelestiaClient {
    pub async fn get_data_available(&self, block_height: u64) -> Result<DataAvailable, Error> {
        let url = format!("data_available/{}", block_height);
        match self.get(&url).send().await {
            Ok(res) => res.json::<DataAvailable>().await,
            Err(err) => Err(err),
        }
    }
    pub async fn get_message(
        &self,
        namespaced_data: String,
        block_height: u64,
    ) -> Result<MessageData, Error> {
        let url = format!(
            "namespaced_data/{}/height/{}",
            namespaced_data, block_height
        );
        match self.get(&url).send().await {
            Ok(res) => res.json::<MessageData>().await,
            Err(err) => Err(err),
        }
    }
    pub async fn submit_pfd(
        &self,
        namespace: &String,
        block_value: &String,
        gas_limit: u64,
    ) -> Result<serde_json::Value, Error> {
        let mut request_builder = self.post("submit_pfd");
        let body = json!({
            "namespace_id": namespace,
            "data": block_value,
            "gas_limit": gas_limit
        });
        println!("Submit_pfd {:?}", block_value);
        request_builder = request_builder.json(&body);
        match request_builder.send().await {
            Ok(res) => res.json().await,
            Err(err) => {
                println!("{:?}", &err);
                Err(err)
            }
        }
    }
}
