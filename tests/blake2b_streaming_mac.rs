use crypto_api_blake2b::{ Blake2bError, Blake2b };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	key___: Vec<u8>,
	input0: Vec<u8>,
	input1: Vec<u8>,
	input2: Vec<u8>,
	mac___: Vec<u8>
}
impl TestVector {
	fn test(&self) {
		// Create hasher and initialize it
		let mut mac = Blake2b::streaming_mac();
		mac.init(&self.key___).unwrap();
		
		// Absorb data
		mac.update(&self.input0).unwrap();
		mac.update(&self.input1).unwrap();
		mac.update(&self.input2).unwrap();
		
		// Compute hash
		let mut buf = vec![0; 64];
		mac.finish(&mut buf).unwrap();
		assert_eq!(buf, self.mac___, "@{} failed", self.line);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"blake2b_streaming_mac.txt"
			=> TestVector{ line, key___, input0, input1, input2, mac___ }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
struct ApiTestVector {
	line: usize,
	test_name_: &'static str,
	key_len___: usize,
	mac_len___: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	fn test(&self) {
		match self.test_name_ {
			"test_init" => self.test_init(),
			"test_finish" => self.test_finish(),
			_ => panic!("Invalid test name @{}", self.line)
		}
	}
	fn test_init(&self) {
		// Create MAC and key
		let mut mac = Blake2b::streaming_mac();
		let key = vec![0; self.key_len___];
		
		// Test init
		let err = mac.init(&key).unwrap_err();
		match err.downcast_ref::<Blake2bError>() {
			Some(Blake2bError::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc,
				"Invalid API-error description @{}", self.line
			),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
	fn test_finish(&self) {
		// Create MAC and key
		let mut mac = Blake2b::streaming_mac();
		
		// Initialize MAC and create parameters
		mac.init(&vec![0; self.key_len___]).unwrap();
		let mut buf = vec![0; self.mac_len___];
		
		// Test finish
		let err = mac.finish(&mut buf).unwrap_err();
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
		"blake2b_streaming_mac_api.txt"
			=> ApiTestVector{ line, test_name_, key_len___, mac_len___, error_desc }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}