#![no_std]

use generic_array::{
    typenum::U16,
    GenericArray,
};
use lorawan_crypto_sys::{
    aes_context as AesContext, aes_decrypt, aes_encrypt, aes_set_key,
    AES_CMAC_Final as aes_cmac_final, AES_CMAC_Init as aes_cmac_init,
    AES_CMAC_SetKey as aes_cmac_setkey, AES_CMAC_Update as aes_cmac_update,
    AES_CMAC_CTX as CmacContext,
};
use lorawan::keys::{CryptoFactory, Decrypter, Encrypter, Mac, AES128};

pub struct EncrypterDecrypter {
    key: GenericArray<u8, U16>,
}

impl EncrypterDecrypter {
    fn get_aes_context(&self) -> AesContext {
        let mut aes_context = AesContext {
            ksch: [0; 240],
            rnd: 0,
        };

        unsafe { aes_set_key(self.key.as_ptr() as *mut u8, 16, &mut aes_context) };

        aes_context
    }

    pub fn new(key: GenericArray<u8, U16>) -> EncrypterDecrypter {
        EncrypterDecrypter { key }
    }
}

impl Encrypter for EncrypterDecrypter {
    fn encrypt_block(&self, block_in: &mut GenericArray<u8, U16>) {
        let mut aes_context = self.get_aes_context();
        let mut block_out: GenericArray<u8, U16> = GenericArray::default();
        unsafe {
            aes_encrypt(
                block_in.as_mut_slice().as_mut_ptr() as *mut u8,
                block_out.as_mut_slice().as_mut_ptr() as *mut u8,
                &mut aes_context as *mut AesContext,
            )
        };
        *block_in = block_out;
    }
}

impl Decrypter for EncrypterDecrypter {
    fn decrypt_block(&self, block_in: &mut GenericArray<u8, U16>) {
        let mut aes_context = self.get_aes_context();
        let mut block_out: GenericArray<u8, U16> = GenericArray::default();
        unsafe {
            aes_decrypt(
                block_in.as_mut_slice().as_mut_ptr() as *mut u8,
                block_out.as_mut_slice().as_mut_ptr() as *mut u8,
                &mut aes_context as *mut AesContext,
            )
        };
        *block_in = block_out;
    }
}

pub struct Cmac {
    context: CmacContext,
}

impl Cmac {
    fn initialize_context(key: GenericArray<u8, U16>) -> CmacContext {
        let mut cmac_context = CmacContext {
            rijndael: AesContext {
                ksch: [0; 240],
                rnd: 0,
            },
            X: [0; 16],
            M_last: [0; 16],
            M_n: 0,
        };

        unsafe {
            aes_cmac_init(&mut cmac_context as *mut CmacContext);
            aes_cmac_setkey(
                &mut cmac_context as *mut CmacContext,
                key.as_ptr() as *mut u8,
            );
        };
        cmac_context
    }

    pub fn new(key: GenericArray<u8, U16>) -> Cmac {
        Cmac {
            context: Self::initialize_context(key),
        }
    }
}

impl Mac for Cmac {
    fn input(&mut self, data: &[u8]) {
        let mut buffer: [u8;256] = [0; 256];

        for (index, item) in data.iter().enumerate() {
            buffer[index] = *item;
        }

        unsafe {
            aes_cmac_update(
                &mut self.context as &mut CmacContext,
                buffer.as_mut_ptr(),
                data.len() as u32,
            )
        }
    }
    fn reset(&mut self) {
        unsafe {
            aes_cmac_init(&mut self.context as *mut CmacContext);
        }
    }

    fn result(self) -> GenericArray<u8, U16> {
        let mut context = self.context;
        let mut result = GenericArray::default();
        unsafe {
            aes_cmac_final(result.as_mut_ptr(), &mut context as *mut CmacContext);
        }
        result
    }
}

#[derive(Default)]
pub struct LorawanCrypto;

impl CryptoFactory for LorawanCrypto {
    type E = EncrypterDecrypter;
    type D = EncrypterDecrypter;
    type M = Cmac;

    fn new_enc(&self, key: &AES128) -> Self::E {
        EncrypterDecrypter::new(GenericArray::clone_from_slice(&key.0))
    }

    fn new_dec(&self, key: &AES128) -> Self::D {
        EncrypterDecrypter::new(GenericArray::clone_from_slice(&key.0))
    }

    fn new_mac(&self, key: &AES128) -> Self::M {
        Cmac::new(GenericArray::clone_from_slice(&key.0))
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use lorawan_encoding::{default_crypto::DefaultFactory, keys::AES128};
    fn get_key() -> AES128 {
        AES128([
            255, 2, 253, 4, 231, 6, 229, 8, 227, 10, 225, 12, 223, 14, 221, 16,
        ])
    }

    fn get_block() -> GenericArray<u8, U16> {
        GenericArray::clone_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    }



    #[test]
    fn test_encrypt() {
        let key = get_key();
        let my_block = {
            let encrypter = LorawanCrypto {}.new_enc(&key);
            let mut block = get_block();
            encrypter.encrypt_block(&mut block);
            block
        };
        let control_block = {
            let encrypter = DefaultFactory {}.new_enc(&key);
            let mut block = get_block();
            encrypter.encrypt_block(&mut block);
            block
        };
        assert_eq!(my_block, control_block);
    }

    #[test]
    fn test_decrypt() {
        let key = get_key();
        let my_block = {
            let decrypter = LorawanCrypto {}.new_dec(&key);
            let mut block = get_block();
            decrypter.encrypt_block(&mut block);
            block
        };
        let control_block = {
            let decrypter = DefaultFactory {}.new_dec(&key);
            let mut block = get_block();
            decrypter.encrypt_block(&mut block);
            block
        };
        assert_eq!(my_block, control_block);
    }

    fn get_cmac_step1() -> [u8; 34] {
        let mut ret = [0; 34];
        ret[5] = 5;
        ret
    }

    fn get_cmac_step2()  -> [u8; 14] {
        let mut ret = [0; 14];
        ret[3] = 5;
        ret
    }

    #[test]
    fn test_cmac() {
        let key = get_key();
        let my_result = {
            let mut mac = LorawanCrypto {}.new_mac(&key);
            let mut step = get_cmac_step1();
            mac.input(&mut step);
            let mut step = get_cmac_step2();
            mac.input(&mut step);
            mac.result()
        };
        let control_result = {
            let mut mac = DefaultFactory {}.new_mac(&key);
            let mut step = get_cmac_step1();
            mac.input(&mut step);
            let mut step = get_cmac_step2();
            mac.input(&mut step);
            mac.result()
        };
        assert_eq!(my_result, control_result);
    }
}
