use std::{ slice, cmp::min };


/// Overflowing add
macro_rules! add {
	($a:expr, $b:expr) => ({ $a.wrapping_add($b) });
	($a:expr, $b:expr, $c:expr) => ({ $a.wrapping_add($b).wrapping_add($c) });
}


const IV: [u64; 8] = [
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];
const SIGMA: [[u8; 16]; 12] = [
	[ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
	[14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
	[11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
	[ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
	[ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
	[ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
	[12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
	[13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
	[ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
	[10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
	[ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
	[14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3]
];


/// A Blake2b state with the real implementation
pub struct B2Impl {
	h: Vec<u64>, // 8
	t: Vec<u64>, // 2
	f: Vec<u64>, // 2
	
	buf: Vec<u8>, // 128
	hash_len: usize
}
impl B2Impl {
	/// Initializes the state as hash with `out_len`
	pub fn init(out_len: usize) -> Self {
		Self::init_kdf(out_len, &[], &[], &[])
	}
	/// Initializes the state as MAC with `out_len` and `key`
	pub fn init_mac(out_len: usize, key: &[u8]) -> Self {
		Self::init_kdf(out_len, key, &[], &[])
	}
	/// Initializes the state as KDF with `out_len`, `base_key`, `salt` and `info`
	pub fn init_kdf(out_len: usize, base_key: &[u8], salt: &[u8], info: &[u8]) -> Self {
		// Validate the output length
		assert!(out_len <= 64, "Output length is too large");
		assert!(base_key.len() <= 64, "Key is too large");
		assert!(salt.len() <= 16, "Salt is too large");
		assert!(info.len() <= 16, "Info is too large");
		
		// Create Blake2b instance
		let mut b2 = Self {
			h: vec![0; 8], t: vec![0; 2], f: vec![0; 2],
			buf: Vec::with_capacity(128),
			hash_len: out_len
		};
		
		// Create parameters
		{
			// Cast the memory behind the hash state to an `u8` slice
			let p =
				unsafe{ slice::from_raw_parts_mut(b2.h.as_mut_ptr() as *mut u8, 64) };
			
			// Set parameters
			p[0] = out_len as u8;
			p[1] = base_key.len() as u8;
			p[2] = 1; // Fan-out
			p[3] = 1; // Depth
			
			// Copy salt and info
			p[32 .. 32 + salt.len()].copy_from_slice(salt);
			p[48 .. 48 + info.len()].copy_from_slice(info);
		}
		
		// Xor the parameters with the IV into `b2.h`
		for i in 0..8 { b2.h[i] ^= IV[i] }
		
		// Hash the key as `0`-padded 128 byte block
		if !base_key.is_empty() {
			b2.update(base_key);
			
			let pad_len = 128 - base_key.len();
			b2.update(&[0; 128][..pad_len]);
		}
		
		b2
	}
	
	/// The compression function
	fn compress(&mut self) {
		/// G function of compression
		fn g(r: usize, i: usize, v: &mut[u64], m: &mut[u64], a: usize, b: usize, c: usize, d: usize)
		{
			v[a] = add!(v[a], v[b], m[SIGMA[r][2 * i + 0] as usize]);
			v[d] = (v[d] ^ v[a]).rotate_right(32);
			v[c] = add!(v[c], v[d]);
			v[b] = (v[b] ^ v[c]).rotate_right(24);
			v[a] = add!(v[a], v[b], m[SIGMA[r][2 * i + 1] as usize]);
			v[d] = (v[d] ^ v[a]).rotate_right(16);
			v[c] = add!(v[c], v[d]);
			v[b] = (v[b] ^ v[c]).rotate_right(63);
		}
		/// One compression round
		fn round(r: usize, v: &mut[u64], m: &mut[u64]) {
			g(r, 0, v, m,  0,  4,  8, 12);
			g(r, 1, v, m,  1,  5,  9, 13);
			g(r, 2, v, m,  2,  6, 10, 14);
			g(r, 3, v, m,  3,  7, 11, 15);
			g(r, 4, v, m,  0,  5, 10, 15);
			g(r, 5, v, m,  1,  6, 11, 12);
			g(r, 6, v, m,  2,  7,  8, 13);
			g(r, 7, v, m,  3,  4,  9, 14);
		}
		
		// Load m
		let mut m = vec![0; 16];
		for i in 0..16 {
			let mut num = [0; 8];
			num.copy_from_slice(&self.buf[i * 8 .. (i + 1) * 8]);
			m[i] = u64::from_le_bytes(num);
		}
		
		// Load v
		let mut v = vec![0; 16];
		v[ 0.. 8].copy_from_slice(&self.h[..8]);
		v[ 8..12].copy_from_slice(&IV[0..4]);
		v[12] = IV[4] ^ self.t[0];
		v[13] = IV[5] ^ self.t[1];
		v[14] = IV[6] ^ self.f[0];
		v[15] = IV[7] ^ self.f[1];
		
		// Do rounds and update state
		for r in 0..12 { round(r, &mut v, &mut m) }
		for i in 0..8 { self.h[i] = self.h[i] ^ v[i] ^ v[i + 8] }
	}
	
	/// Updates the state with `data`
	pub fn update(&mut self, mut data: &[u8]) -> &mut Self {
		// Process data
		while !data.is_empty() {
			// Fill buffer
			let to_copy = min(128 - self.buf.len(), data.len());
			self.buf.extend_from_slice(&data[..to_copy]);
			data = &data[to_copy..];
			
			// Process full block if possible and we are not the last block
			if self.buf.len() == 128 && !data.is_empty() {
				// Increment counter
				self.t[0] = add!(self.t[0], 128);
				if self.t[0] < 128 { self.t[1] += 1 }
				
				// Compress block and clear buffer
				self.compress();
				self.buf.clear();
			}
		}
		self
	}
	
	/// Finalizes the state and computes the digest into `buf`
	pub fn finish(&mut self, buf: &mut[u8]) {
		// Validate `buf` and the state
		assert_eq!(buf.len(), self.hash_len, "Invalid buffer length");
		assert_eq!(self.f[0], 0, "Final hash has already been computed");
		
		// Increment counter
		self.t[0] = add!(self.t[0], self.buf.len() as u64);
		if self.t[0] < self.buf.len() as u64 { self.t[1] += 1 }
		
		// Set final block
		self.f[0] = u64::max_value();
		
		// `0`-pad the buffer to a complete block length
		self.buf.resize(128, 0);
		self.compress();
		
		// Store the entire 512-bit hash in `out`
		let mut out = vec![0; 64];
		for i in 0..8 {
			let num = self.h[i].to_le_bytes();
			out[i * 8 .. (i + 1) * 8].copy_from_slice(&num);
		}
		buf.copy_from_slice(&out[..buf.len()])
	}
	
	pub fn hash_len(&self) -> usize {
		self.hash_len
	}
}