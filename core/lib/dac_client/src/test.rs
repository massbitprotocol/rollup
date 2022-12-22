#[cfg(test)]
pub mod test {
    use reqwest::Error;
    use crate::{create_namespace, DACClient};

    #[tokio::test]
    async fn test_dac_connection() -> Result<(), Error> {
        let dac_client = DACClient::new();
        let data_avaiable = dac_client.get_data_available(300).await;
        println!("{:?}", data_avaiable);
        let namespace = create_namespace();
        println!("{:?}" ,namespace);
        Ok(())
    }
}