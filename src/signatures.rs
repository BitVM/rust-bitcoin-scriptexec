use bitcoin::secp256k1::{self, XOnlyPublicKey};
use bitcoin::sighash::{Annex, Prevouts, TapSighashType};

use crate::*;

impl Exec {
    /// [pk] should be passed as 32-bytes.
    pub fn check_sig_schnorr(&mut self, sig: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        assert_eq!(pk.len(), 32);

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ExecError::SchnorrSigSize);
        }

        let pk = XOnlyPublicKey::from_slice(pk).expect("TODO(stevenroose) what to do here?");
        let (sig, hashtype) = if sig.len() == 65 {
            let b = *sig.last().unwrap();
            let sig = secp256k1::schnorr::Signature::from_slice(&sig[0..sig.len() - 1])
                .map_err(|_| ExecError::SchnorrSig)?;

            if b == TapSighashType::Default as u8 {
                return Err(ExecError::SchnorrSigHashtype);
            }
            //TODO(stevenroose) core does not error here
            let sht =
                TapSighashType::from_consensus_u8(b).map_err(|_| ExecError::SchnorrSigHashtype)?;
            (sig, sht)
        } else {
            let sig = secp256k1::schnorr::Signature::from_slice(sig)
                .map_err(|_| ExecError::SchnorrSig)?;
            (sig, TapSighashType::Default)
        };

        let (leaf_hash, annex) = self.tx.taproot_annex_scriptleaf.as_ref().unwrap();
        let sighash = self
            .sighashcache
            .taproot_signature_hash(
                self.tx.input_idx,
                &Prevouts::All(&self.tx.prevouts),
                annex
                    .as_ref()
                    .map(|a| Annex::new(a).expect("we checked annex prefix before")),
                Some((*leaf_hash, self.last_codeseparator_pos.unwrap_or(u32::MAX))),
                hashtype,
            )
            .expect("TODO(stevenroose) seems to only happen if prevout index out of bound");

        if self.secp.verify_schnorr(&sig, &sighash.into(), &pk) != Ok(()) {
            return Err(ExecError::SchnorrSig);
        }

        Ok(())
    }
}
