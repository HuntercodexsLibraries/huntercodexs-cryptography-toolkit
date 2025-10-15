package com.huntercodexs.cryptography.toolkit.algorithm.impl.simplifier;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.contract.simplifier.CryptographyContractSimplifierAES;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_INSTANCE_TYPE_FOR_CIPHER;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm<Object> {

    @Override
    public String encrypt(Object contract, String dataToEncrypt) {
        try {
            return encryptAesSimplifier(
                    dataToEncrypt,
                    ((CryptographyContractSimplifierAES) contract).getCryptoSecretKey(),
                    ((CryptographyContractSimplifierAES) contract).getCryptoSpecIv());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    @Override
    public String decrypt(Object contract, String dataToDecrypt) {
        try {
            return decryptAesSimplifier(
                    dataToDecrypt,
                    ((CryptographyContractSimplifierAES) contract).getCryptoSecretKey(),
                    ((CryptographyContractSimplifierAES) contract).getCryptoSpecIv());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    private String encryptAesSimplifier(String plainText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptAesSimplifier(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}
