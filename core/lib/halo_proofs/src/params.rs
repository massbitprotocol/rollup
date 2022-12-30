use crate::hasher::bn256::Bn256RescueParams;
use lazy_static::lazy_static;

lazy_static! {
  //pub static ref RESCUE_PARAMS: Bn256RescueParams = Bn256RescueParams::new_checked_2_into_1();
  pub static ref BN256_DEFAULT_PARAMS: Bn256RescueParams = Bn256RescueParams::empty();
  //  Special address for the account used in the nft logic
  //pub static ref NFT_STORAGE_ACCOUNT_ADDRESS: Address =
  //    Address::from_str("ffffffffffffffffffffffffffffffffffffffff").unwrap();
}
