use crypto_api_blake2b::{ Blake2bError, Blake2b };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	input_: Vec<u8>,
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
		// Create hasher
		let hash = Blake2b::hash();
		
		// Hash data and verify hash
		let mut buf = vec![0; 64];
		hash.hash(&mut buf, &self.input_).unwrap();
		assert_eq!(buf, self.output, "@{} failed", self.line);
	}
	fn test_varlen(&self) {
		// Create hasher
		let hash = Blake2b::varlen_hash();
		
		// Hash data and verify hash
		let mut buf = vec![0; self.output.len()];
		hash.varlen_hash(&mut buf, &self.input_).unwrap();
		assert_eq!(buf, self.output, "@{} failed", self.line);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"blake2b_hash.txt"
			=> TestVector{ line, input_, output }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
struct ApiTestVector {
	line: usize,
	output_len: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	fn test(&self) {
		match self.error_desc {
			"Invalid buffer length" => self.test_constlen(),
			_ => self.test_varlen()
		}
	}
	fn test_constlen(&self) {
		// Create hasher
		let hash = Blake2b::hash();
		
		// Create the invalid output buffer and compare the error
		let mut buf = vec![0; self.output_len];
		let err = hash.hash(&mut buf, b"Testolope").unwrap_err();
		match err.downcast_ref::<Blake2bError>() {
			Some(Blake2bError::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc,
				"Invalid API-error description @{}", self.line
			),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
	fn test_varlen(&self) {
		// Create hasher
		let hash = Blake2b::varlen_hash();
		
		// Create the invalid output buffer and compare the error
		let mut buf = vec![0; self.output_len];
		let err = hash.varlen_hash(&mut buf, b"Testolope").unwrap_err();
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
		"blake2b_hash_api.txt"
			=> ApiTestVector{ line, output_len, error_desc }
	);
	// Test all vectors
	for vector in vectors { vector.test() }
}