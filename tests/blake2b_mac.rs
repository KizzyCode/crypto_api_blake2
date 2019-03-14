use crypto_api_blake2b::{ Blake2bError, Blake2b };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	key__: Vec<u8>,
	input: Vec<u8>,
	mac__: Vec<u8>,
}
impl TestVector {
	pub fn test(&self) {
		// Create MAC
		let mac = Blake2b::mac();
		
		// Derive MAC
		let mut buf = vec![0; self.mac__.len()];
		mac.authenticate(&mut buf, &self.input, &self.key__).unwrap();
		assert_eq!(buf, self.mac__);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"blake2b_mac.txt"
			=> TestVector{ line, key__, input, mac__ }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
struct ApiTestVector {
	line: usize,
	input_len_: usize,
	key_len___: usize,
	mac_len___: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	fn test(&self) {
		// Create MAC
		let mac = Blake2b::mac();
		
		// Create parameters
		let input = vec![0; self.input_len_];
		let key = vec![0; self.key_len___];
		let mut buf = vec![0; self.mac_len___];
		
		// Test API
		let err = mac.authenticate(&mut buf, &input, &key).unwrap_err();
		match err.downcast_ref::<Blake2bError>() {
			Some(Blake2bError::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc,
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
		"blake2b_mac_api.txt" => ApiTestVector {
			line, input_len_, key_len___,
			mac_len___, error_desc
		}
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}