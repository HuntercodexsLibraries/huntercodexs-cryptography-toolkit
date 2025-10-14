package com.huntercodexs.cryptography.toolkit.algorithm.impl.simplifier;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

/**
 * 3DES (DESede)
 * */
public class CryptographyAlgorithm3DESImpl implements CryptographyAlgorithm {

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        try {
            return encryptTripleDesSimplifier(dataToEncrypt, contract.getCryptoSecretKey(), contract.getCryptoSpecIv());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        try {
            return decryptTripleDesSimplifier(dataToDecrypt, contract.getCryptoSecretKey(), contract.getCryptoSpecIv());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    private String encryptTripleDesSimplifier(String plainText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptTripleDesSimplifier(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}