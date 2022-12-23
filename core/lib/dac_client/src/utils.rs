use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub fn string_to_hex(data: &String) -> String {
    hex::encode(data)
}

pub fn hex_to_string(hexstring: &String) -> String {
    String::from("")
}
