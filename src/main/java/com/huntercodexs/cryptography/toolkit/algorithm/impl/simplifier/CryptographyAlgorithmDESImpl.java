package com.huntercodexs.cryptography.toolkit.algorithm.impl.simplifier;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

/**
 * DES (Symmetric)
 * */
public class CryptographyAlgorithmDESImpl implements CryptographyAlgorithm {

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        try {
            return encryptDesSimplifier(dataToEncrypt, contract.getCryptoSecretKey(), contract.getCryptoSpecIv());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        try {
            return decryptDesSimplifier(dataToDecrypt, contract.getCryptoSecretKey(), contract.getCryptoSpecIv());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    private String encryptDesSimplifier(String plainText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptDesSimplifier(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}
