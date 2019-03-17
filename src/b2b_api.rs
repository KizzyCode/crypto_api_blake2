use crate::{ Blake2Error, b2b_impl::B2Impl };
use crypto_api::{
	rng::{ SecureRng, SecKeyGen }, kdf::{ KdfInfo, Kdf },
	mac::{ MacInfo, Mac, VarlenMac, StreamingMac, StreamingVarlenMac },
	hash::{ HashInfo, Hash, VarlenHash, StreamingHash, StreamingVarlenHash }
};
use std::error::Error;


/// Checks if `$v` is in the range `$r`
macro_rules! check_in {
    ($v:expr, $r:expr) => ({
    	if $v < *$r.start() {
    		Err(Blake2Error::ApiMisuse(concat!("`", stringify!($v), "` is too small")))?
    	}
    	if $v > *$r.end() {
    		Err(Blake2Error::ApiMisuse(concat!("`", stringify!($v), "` is too large")))?
    	}
    });
}
/// Checks if `$v` is equal to `$e`
macro_rules! check_eq {
    ($v:expr, $e:expr) => ({
    	if $v != $e {
    		Err(Blake2Error::ApiMisuse(concat!("`", stringify!($v), "` is invalid")))?
    	}
    })
}


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
	/// Creates a `VarlenMac` instance with `Blake2b` as underlying MAC
	pub fn varlen_mac() -> Box<dyn VarlenMac> {
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
	/// Creates a `StreamingVarlenMac` instance with `Blake2b` as underlying MAC
	pub fn streaming_varlen_mac() -> Box<dyn StreamingVarlenMac> {
		Box::new(Self(None))
	}
	
	/// Returns info about the hash
	fn hash_info() -> HashInfo {
		HashInfo{ name: "Blake2b", hash_len: 64, hash_len_r: 1..64 }
	}
	/// Returns info about the MAC
	fn mac_info() -> MacInfo {
		MacInfo{ name: "Blake2b", is_otm: false, mac_len: 64, mac_len_r: 1..64, key_len_r: 1..64 }
	}
	/// Returns info about the KDF
	fn kdf_info() -> KdfInfo {
		KdfInfo {
			name: "Blake2b", output_len_r: 1..64, key_len_r: 1..64,
			salt_len_r: 0..16, info_len_r: 0..16
		}
	}
}

impl SecKeyGen for Blake2b {
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut SecureRng)
		-> Result<usize, Box<dyn Error + 'static>>
	{
		check_in!(buf.len(), 1..=64);
		
		rng.random(buf)?;
		Ok(buf.len())
	}
}

impl Hash for Blake2b {
	fn info(&self) -> HashInfo {
		Self::hash_info()
	}
	
	fn hash(&self, buf: &mut[u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		check_eq!(buf.len(), 64);
		self.varlen_hash(buf, data)
	}
}
impl VarlenHash for Blake2b {
	fn varlen_hash(&self, buf: &mut[u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		check_in!(buf.len(), 1..=64);
		
		B2Impl::init(buf.len()).update(data).finish(buf);
		Ok(buf.len())
	}
}

impl Mac for Blake2b {
	fn info(&self) -> MacInfo {
		Self::mac_info()
	}
	
	fn auth(&self, buf: &mut[u8], data: &[u8], key: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		check_eq!(buf.len(), 64);
		self.varlen_auth(buf, data, key)
	}
}
impl VarlenMac for Blake2b {
	fn varlen_auth(&self, buf: &mut[u8], data: &[u8], key: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		check_in!(buf.len(), 1..=64);
		check_in!(key.len(), 1..=64);
		
		B2Impl::init_mac(buf.len(), key).update(data).finish(buf);
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
		check_in!(buf.len(), 1..=64);
		check_in!(base_key.len(), 1..=64);
		check_in!(salt.len(), 0..=16);
		check_in!(info.len(), 0..=16);
		
		B2Impl::init_kdf(buf.len(), base_key, salt, info).finish(buf);
		Ok(())
	}
}

impl StreamingHash for Blake2b {
	fn info(&self) -> HashInfo {
		let mut info = Self::hash_info();
		if let Some(s) = self.0.as_ref() { info.hash_len = s.hash_len() }
		info
	}
	
	fn init(&mut self) -> Result<(), Box<dyn Error + 'static>> {
		self.0 = Some(B2Impl::init(64));
		Ok(())
	}
	fn update(&mut self, input: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		self.0.as_mut()
			.ok_or(Blake2Error::ApiMisuse("The hash is not initialized"))?
			.update(input);
		Ok(())
	}
	fn finish(&mut self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		let mut state = self.0.take()
			.ok_or(Blake2Error::ApiMisuse("The hash is not initialized"))?;
		check_eq!(buf.len(), state.hash_len());
		
		state.finish(buf);
		Ok(buf.len())
	}
}
impl StreamingVarlenHash for Blake2b {
	fn varlen_init(&mut self, hash_len: usize) -> Result<(), Box<dyn Error + 'static>> {
		check_in!(hash_len, 1..=64);
		
		self.0 = Some(B2Impl::init(hash_len));
		Ok(())
	}
}

impl StreamingMac for Blake2b {
	fn info(&self) -> MacInfo {
		let mut info = Self::mac_info();
		if let Some(s) = self.0.as_ref() { info.mac_len = s.hash_len() }
		info
	}
	
	fn init(&mut self, key: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		check_in!(key.len(), 1..=64);
		
		self.0 = Some(B2Impl::init_mac(64, key));
		Ok(())
	}
	fn update(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		self.0.as_mut()
			.ok_or(Blake2Error::ApiMisuse("The MAC is not initialized"))?
			.update(data);
		Ok(())
	}
	fn finish(&mut self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		let mut state = self.0.take()
			.ok_or(Blake2Error::ApiMisuse("The MAC is not initialized"))?;
		check_eq!(buf.len(), state.hash_len());
		
		state.finish(buf);
		Ok(buf.len())
	}
}
impl StreamingVarlenMac for Blake2b {
	fn varlen_init(&mut self, mac_len: usize, key: &[u8]) -> Result<(), Box<dyn Error + 'static>> {
		check_in!(mac_len, 1..=64);
		check_in!(key.len(), 1..=64);
		
		self.0 = Some(B2Impl::init_mac(mac_len, key));
		Ok(())
	}
}