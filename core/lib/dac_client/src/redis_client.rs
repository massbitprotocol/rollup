use crate::REDIS_CONN_URL;
use std::env;

#[derive(Debug, Clone)]
pub struct RedisClient {}
pub fn get_connection() -> redis::Connection {
    //format - host:port
    //let redis_host_name = env::var("REDIS_HOSTNAME").expect("missing environment variable REDIS_HOSTNAME");
    //let redis_password = env::var("REDIS_PASSWORD").unwrap_or_default();

    //if Redis server needs secure connection
    // let uri_scheme = match env::var("IS_TLS") {
    //     Ok(_) => "rediss",
    //     Err(_) => "redis",
    // };

    //let redis_conn_url = format!("{}://:{}@{}", uri_scheme, redis_password, redis_host_name);
    //println!("{}", redis_conn_url);
    let redis_conn_url = (*REDIS_CONN_URL).to_string();
    redis::Client::open(redis_conn_url)
        .expect("Invalid connection URL")
        .get_connection()
        .expect("failed to connect to Redis")
}
impl RedisClient {
    pub fn default() -> Self {
        Self {}
    }
    pub fn store_block_data(&self, key: String, data: String) {
        let mut conn = get_connection();
        println!("******* Running SET, GET, INCR commands *******");

        let _: () = redis::cmd("SET")
            .arg(key.as_str())
            .arg(data)
            .query(&mut conn)
            .expect(format!("failed to execute SET for {:?}", key).as_str());

        let stored_value: String = redis::cmd("GET")
            .arg(key.as_str())
            .query(&mut conn)
            .expect(format!("failed to execute GET for {:?}", key).as_str());
        println!("value for {} = {}", &key, stored_value);
    }
}
