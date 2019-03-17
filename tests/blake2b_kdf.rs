use crypto_api_blake2b::{ Blake2Error, Blake2b };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	base_key: Vec<u8>,
	salt____: Vec<u8>,
	info____: Vec<u8>,
	key_____: Vec<u8>
}
impl TestVector {
	pub fn test(&self) {
		// Create KDF
		let kdf = Blake2b::kdf();
		
		// Derive key
		let mut buf = vec![0; self.key_____.len()];
		kdf.derive(&mut buf, &self.base_key, &self.salt____, &self.info____).unwrap();
		assert_eq!(buf, self.key_____);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"blake2b_kdf.txt"
			=> TestVector{ line, base_key, salt____, info____, key_____ }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
struct ApiTestVector {
	line: usize,
	base_key_len: usize,
	salt_len____: usize,
	info_len____: usize,
	output_len__: usize,
	error_desc__: &'static str
}
impl ApiTestVector {
	fn test(&self) {
		// Create KDF
		let kdf = Blake2b::kdf();
		
		// Create parameters
		let base_key = vec![0; self.base_key_len];
		let salt = vec![0; self.salt_len____];
		let info = vec![0; self.info_len____];
		let mut buf = vec![0; self.output_len__];
		
		// Test API
		let err = kdf.derive(&mut buf, &base_key, &salt, &info).unwrap_err();
		match err.downcast_ref::<Blake2Error>() {
			Some(Blake2Error::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc__,
				"Invalid API-error description @{}", self.line
			),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
}
#[test]
fn test_api() {
	// Read test vectors
	let vectors: Vec<ApiTestVector> = read_test_vectors!(
		"blake2b_kdf_api.txt" => ApiTestVector {
			line, base_key_len, salt_len____, info_len____,
			output_len__, error_desc__
		}
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}