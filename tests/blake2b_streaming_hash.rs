use crypto_api_blake2b::{ Blake2Error, Blake2b };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	input0: Vec<u8>,
	input1: Vec<u8>,
	input2: Vec<u8>,
	input3: Vec<u8>,
	output: Vec<u8>
}
impl TestVector {
	pub fn test(&self) {
		match self.output.len() {
			64 => self.test_constlen(),
			_ => self.test_varlen()
		}
	}
	fn test_constlen(&self) {
		// Create hasher and initialize it
		let mut hash = Blake2b::streaming_hash();
		hash.init().unwrap();
		
		// Absorb data
		hash.update(&self.input0).unwrap();
		hash.update(&self.input1).unwrap();
		hash.update(&self.input2).unwrap();
		hash.update(&self.input3).unwrap();
		
		// Compute hash
		let mut buf = vec![0; 64];
		hash.finish(&mut buf).unwrap();
		assert_eq!(buf, self.output, "@{} failed", self.line);
	}
	fn test_varlen(&self) {
		// Create hasher and initialize it
		let mut hash = Blake2b::streaming_varlen_hash();
		hash.varlen_init(self.output.len()).unwrap();
		
		// Absorb data
		hash.update(&self.input0).unwrap();
		hash.update(&self.input1).unwrap();
		hash.update(&self.input2).unwrap();
		hash.update(&self.input3).unwrap();
		
		// Compute hash
		let mut buf = vec![0; self.output.len()];
		hash.finish(&mut buf).unwrap();
		assert_eq!(buf, self.output, "@{} failed", self.line);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"blake2b_streaming_hash.txt"
			=> TestVector{ line, input0, input1, input2, input3, output }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
struct ApiTestVector {
	line: usize,
	test_name_: &'static str,
	hash_len__: usize,
	buffer_len: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	fn test(&self) {
		match self.test_name_ {
			"test_varlen_init" => self.test_varlen_init(),
			"test_varlen_finish" => self.test_varlen_finish(),
			"test_constlen_finish" => self.test_constlen_finish(),
			_ => panic!("Invalid test name @{}", self.line)
		}
	}
	fn test_varlen_init(&self) {
		// Create hasher and initialize it
		let mut hash = Blake2b::streaming_varlen_hash();
		
		// Test initialization error
		let err = hash.varlen_init(self.hash_len__).unwrap_err();
		match err.downcast_ref::<Blake2Error>() {
			Some(Blake2Error::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc,
				"Invalid API-error description @{}", self.line
			),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
	fn test_varlen_finish(&self) {
		// Create hasher and initialize it
		let mut hash = Blake2b::streaming_varlen_hash();
		hash.varlen_init(self.hash_len__).unwrap();
		
		// Test finalization error
		let mut buf = vec![0; self.buffer_len];
		let err = hash.finish(&mut buf).unwrap_err();
		match err.downcast_ref::<Blake2Error>() {
			Some(Blake2Error::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc,
				"Invalid API-error description @{}", self.line
			),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
	fn test_constlen_finish(&self) {
		// Create hasher and initialize it
		let mut hash = Blake2b::streaming_hash();
		hash.init().unwrap();
		
		// Test finish error
		let mut buf = vec![0; self.buffer_len];
		let err = hash.finish(&mut buf).unwrap_err();
		match err.downcast_ref::<Blake2Error>() {
			Some(Blake2Error::ApiMisuse(desc)) => assert_eq!(
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
		"blake2b_streaming_hash_api.txt"
			=> ApiTestVector{ line, test_name_, hash_len__, buffer_len, error_desc }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}