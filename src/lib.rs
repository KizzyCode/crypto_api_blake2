mod b2b_impl;
mod b2b_api;

pub use crate::b2b_api::Blake2b;
pub use crypto_api;
use std::{
	error::Error,
	fmt::{ Display, Formatter, Result as FmtResult }
};


/// A Blake2 related error
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Blake2Error {
	/// An API misuse happened
	ApiMisuse(&'static str)
}
impl Display for Blake2Error {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "{:?}", self)
	}
}
impl Error for Blake2Error {}