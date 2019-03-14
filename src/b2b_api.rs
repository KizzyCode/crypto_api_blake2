use crate::{ Blake2bError, b2b_impl::B2Impl };
use crypto_api::{
	rng::{ SecureRng, SecKeyGen }, kdf::{ KdfInfo, Kdf }, mac::{ MacInfo, Mac, StreamingMac },
	hash::{ HashInfo, Hash, VarlenHash, StreamingHash, StreamingVarlenHash }
};
use std::error::Error;


/// An implementation of [Blake2b](https://blake2.net/blake2.pdf)
pub struct Blake2b(Option<B2Impl>);
impl Blake2b {
	/// Creates a `Hash` instance with `Blake2b` as underlying hash
	pub fn hash() -> Box<dyn Hash> {
		Box::new(Self(None))
	}
	/// Creates a `VarlenHash` instance with `Blake2b` as underlying hash
	pub fn varlen_hash() -> Box<dyn VarlenHash> {
		Box::new(Self(None))
	}
	/// Creates a `Mac` instance with `Blake2b` as underlying MAC
	pub fn mac() -> Box<dyn Mac> {
		Box::new(Self(None))
	}
	/// Creates a `Kdf` instance with `Blake2b` as underlying KDF
	pub fn kdf() -> Box<dyn Kdf> {
		Box::new(Self(None))
	}
	
	/// Creates a `StreamingHash` instance with `Blake2b` as underlying hash
	pub fn streaming_hash() -> Box<dyn StreamingHash> {
		Box::new(Self(None))
	}
	/// Creates a `StreamingVarlenHash` instance with `Blake2b` as underlying hash
	pub fn streaming_varlen_hash() -> Box<dyn StreamingVarlenHash> {
		Box::new(Self(None))
	}
	/// Creates a `StreamingMac` instance with `Blake2b` as underlying MAC
	pub fn streaming_mac() -> Box<dyn StreamingMac> {
		Box::new(Self(None))
	}
	
	/// Returns info about the hash
	fn hash_info() -> HashInfo {
		HashInfo{ name: "Blake2b", hash_len: 64, hash_len_min: 1, hash_len_max: 64 }
	}
	/// Returns info about the MAC
	fn mac_info() -> MacInfo {
		MacInfo {
			name: "Blake2b", is_one_time_mac: false,
			mac_len: 64, key_len_min: 1, key_len_max: 64
		}
	}
	/// Returns info about the KDF
	fn kdf_info() -> KdfInfo {
		KdfInfo {
			name: "Blake2b", output_len_min: 1, output_len_max: 64, key_len_min: 1, key_len_max: 64,
			salt_len_min: 0, salt_len_max: 16, info_len_min: 0, info_len_max: 16
		}
	}
}
impl SecKeyGen for Blake2b {
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut SecureRng)
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Validate input
		if buf.len() < 1 { Err(Blake2bError::ApiMisuse("Buffer is too small"))? }
		if buf.len() > 64 { Err(Blake2bError::ApiMisuse("Buffer is too large"))? }
		
		rng.random(buf)?;
		Ok(buf.len())
	}
}
impl Hash for Blake2b {
	fn info(&self) -> HashInfo {
		Self::hash_info()
	}
	
	fn hash(&self, buf: &mut[u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		// Validate input
		if buf.len() != 64 { Err(Blake2bError::ApiMisuse("Invalid buffer length"))? }
		
		B2Impl::init(buf.len()).update(data).finish(buf);
		Ok(buf.len())
	}
}
impl VarlenHash for Blake2b {
	fn varlen_hash(&self, buf: &mut[u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		// Validate input
		if buf.len() < 1 { Err(Blake2bError::ApiMisuse("Buffer is too small"))? }
		if buf.len() > 64 { Err(Blake2bError::ApiMisuse("Buffer is too large"))? }
		
		B2Impl::init(buf.len()).update(data).finish(buf);
		Ok(buf.len())
	}
}
impl Mac for Blake2b {
	fn info(&self) -> MacInfo {
		Self::mac_info()
	}
	
	fn authenticate(&self, buf: &mut[u8], data: &[u8], key: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Validate input
		if buf.len() != 64 { Err(Blake2bError::ApiMisuse("Invalid buffer length"))? }
		if key.len() < 1 { Err(Blake2bError::ApiMisuse("Key is too small"))? }
		if key.len() > 64 { Err(Blake2bError::ApiMisuse("Key is too large"))? }
		
		B2Impl::init_mac(64, key).update(data).finish(buf);
		Ok(buf.len())
	}
}
impl Kdf for Blake2b {
	fn info(&self) -> KdfInfo {
		Self::kdf_info()
	}
	
	fn derive(&self, buf: &mut[u8], base_key: &[u8], salt: &[u8], info: &[u8])
		-> Result<(), Box<dyn Error + 'static>>
	{
		// Validate input
		if buf.len() < 1 { Err(Blake2bError::ApiMisuse("Buffer is too small"))? }
		if buf.len() > 64 { Err(Blake2bError::ApiMisuse("Buffer is too large"))? }
		if base_key.len() < 1 { Err(Blake2bError::ApiMisuse("Base key is too small"))? }
		if base_key.len() > 64 { Err(Blake2bError::ApiMisuse("Base key is too large"))? }
		if salt.len() > 16 { Err(Blake2bError::ApiMisuse("Salt is too large"))? }
		if info.len() > 16 { Err(Blake2bError::ApiMisuse("Info is too large"))? }
		
		B2Impl::init_kdf(buf.len(), base_key, salt, info).finish(buf);
		Ok(())
	}
}
impl StreamingHash for Blake2b {
	fn info(&self) -> HashInfo {
		Self::hash_info()
	}
	
	fn init(&mut self) -> Result<(), Box<dyn Error + 'static>> {
		self.0 = Some(B2Impl::init(64));
		Ok(())
	}
	fn update(&mut self, input: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		self.0.as_mut()
			.ok_or(Blake2bError::ApiMisuse("The hash is not initialized"))?
			.update(input);
		Ok(())
	}
	fn finish(&mut self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		// Unwrap state
		let mut state = self.0.take()
			.ok_or(Blake2bError::ApiMisuse("The hash is not initialized"))?;
		
		// Validate input and compute hash
		if buf.len() != state.hash_len() { Err(Blake2bError::ApiMisuse("Invalid buffer length"))? }
		state.finish(buf);
		Ok(buf.len())
	}
}
impl StreamingVarlenHash for Blake2b {
	fn varlen_init(&mut self, hash_len: usize) -> Result<(), Box<dyn Error + 'static>> {
		// Validate input
		if hash_len < 1 { Err(Blake2bError::ApiMisuse("Hash length is too small"))? }
		if hash_len > 64 { Err(Blake2bError::ApiMisuse("Hash length is too large"))? }
		
		self.0 = Some(B2Impl::init(hash_len));
		Ok(())
	}
}
impl StreamingMac for Blake2b {
	fn info(&self) -> MacInfo {
		Self::mac_info()
	}
	
	fn init(&mut self, key: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		// Validate input
		if key.len() < 1 { Err(Blake2bError::ApiMisuse("Key is too small"))? }
		if key.len() > 64 { Err(Blake2bError::ApiMisuse("Key is too large"))? }
		
		self.0 = Some(B2Impl::init_mac(64, key));
		Ok(())
	}
	fn update(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		self.0.as_mut()
			.ok_or(Blake2bError::ApiMisuse("The MAC is not initialized"))?
			.update(data);
		Ok(())
	}
	fn finish(&mut self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		// Validate input
		if buf.len() != 64 { Err(Blake2bError::ApiMisuse("Invalid buffer length"))? }
		
		self.0.take()
			.ok_or(Blake2bError::ApiMisuse("The MAC is not initialized"))?
			.finish(buf);
		Ok(buf.len())
	}
}