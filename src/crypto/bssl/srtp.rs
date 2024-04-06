use boring::symm::{Cipher, Crypter, Mode};

use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::CryptoError;

pub struct BsslSrtpCryptoImpl;

impl SrtpCryptoImpl for BsslSrtpCryptoImpl {
    type Aes128CmSha1_80 = BsslAes128CmSha1_80;
    type AeadAes128Gcm = BsslAeadAes128Gcm;

    fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
        let mut aes =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).expect("AES deriver");

        // Run AES
        let count = aes.update(input, output).expect("AES update");
        let rest = aes.finalize(&mut output[count..]).expect("AES finalize");

        assert_eq!(count + rest, 16 + 16); // input len + block size
    }
}

pub struct BsslAes128CmSha1_80 {
    t: Cipher,
    key: aes_128_cm_sha1_80::AesKey,
}

impl aes_128_cm_sha1_80::CipherCtx for BsslAes128CmSha1_80 {
    fn new(key: aes_128_cm_sha1_80::AesKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let t = Cipher::aes_128_ctr();

        BsslAes128CmSha1_80 { t, key }
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut ctx = Crypter::new(self.t, Mode::Encrypt, &self.key[..], Some(iv))?;
        let count = ctx.update(input, output)?;
        ctx.finalize(&mut output[count..])?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut ctx = Crypter::new(self.t, Mode::Decrypt, &self.key[..], Some(iv))?;
        let count = ctx.update(input, output)?;
        ctx.finalize(&mut output[count..])?;
        Ok(())
    }
}

pub struct BsslAeadAes128Gcm{
    t: Cipher,
    key: aead_aes_128_gcm::AeadKey,
}

impl aead_aes_128_gcm::CipherCtx for BsslAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let t = Cipher::aes_128_gcm();

        BsslAeadAes128Gcm { t, key }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        let mut ctx = Crypter::new(self.t, Mode::Encrypt, &self.key[..], Some(iv))?;
        ctx.pad(false);

        // Add the additional authenticated data, omitting the output argument informs
        // BoringSSL that we are providing AAD.
        ctx.aad_update(aad)?;

        let count = ctx.update(input, output)?;
        let final_count = ctx.finalize(&mut output[count..])?;

        // Get the authentication tag and append it to the output
        let tag_offset = count + final_count;
        ctx.get_tag(&mut output[tag_offset..tag_offset + aead_aes_128_gcm::TAG_LEN])?;

        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // This needs to be converted to an error maybe
        assert!(input.len() >= aead_aes_128_gcm::TAG_LEN);

        let (cipher_text, tag) = input.split_at(input.len() - aead_aes_128_gcm::TAG_LEN);

        let mut ctx = Crypter::new(self.t, Mode::Decrypt, &self.key[..], Some(iv))?;

        // Add the additional authenticated data, omitting the output argument informs
        // BoringSSL that we are providing AAD.
        // With this the authentication tag will be verified.
        for aad in aads {
            ctx.aad_update(aad)?;
        }

        ctx.set_tag(tag)?;

        let count = ctx.update(cipher_text, output)?;

        let final_count = ctx.finalize(&mut output[count..])?;

        Ok(count + final_count)
    }
}
