

use bitcoin::secp256k1::{self, XOnlyPublicKey};
use bitcoin::sighash::{TapSighashType, Prevouts};

use crate::Exec;
use crate::error::ExecError;

lazy_static::lazy_static! {
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

impl Exec {
	/// [pk] should be passed as 32-bytes.
	pub fn check_sig_schnorr(
		&mut self,
		sig: &[u8],
		pk: &[u8],
		input_idx: usize,
	) -> Result<(), ExecError> {
		assert_eq!(pk.len(), 32);

		if sig.len() != 64 && sig.len() != 65 {
			return Err(ExecError::SchnorrSigSize);
		}

		let pk = XOnlyPublicKey::from_slice(pk).expect("TODO(stevenroose) what to do here?");
		let (sig, hashtype) = if sig.len() == 65 {
			let b = *sig.last().unwrap();
			let sig = secp256k1::schnorr::Signature::from_slice(&sig[0..sig.len()-2])
				.map_err(|_| ExecError::SchnorrSig)?;

			if b == TapSighashType::Default as u8 {
				return Err(ExecError::SchnorrSigHashtype);
			}
			//TODO(stevenroose) core does not error here
			let sht = TapSighashType::from_consensus_u8(b)
				.map_err(|_| ExecError::SchnorrSigHashtype)?;
			(sig, sht)
		} else {
			let sig = secp256k1::schnorr::Signature::from_slice(sig)
				.map_err(|_| ExecError::SchnorrSig)?;
			(sig, TapSighashType::Default)
		};

		let sighash = self.sighashcache.taproot_signature_hash(
			input_idx,
			&Prevouts::All(&self.tx.prevouts),
			None, //TODO(stevenroose) annex
			None, //TODO(stevenroose) leaf hash op code separator
			hashtype,
		).expect("TODO(stevenroose) seems to only happen if prevout index out of bound");

		if SECP.verify_schnorr(&sig, &sighash.into(), &pk) != Ok(()) {
			return Err(ExecError::SchnorrSig);
		}

		Ok(())
	}
}
