package com.huntercodexs.cryptography.toolkit.algorithm.impl;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/** 
 * RSA (Asymmetric) 
 * */
public class CryptographyAlgorithmRSAImpl implements CryptographyAlgorithm {

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        try {
            return rsaEncrypt(dataToEncrypt, contract.getPublicKey());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        try {
            return rsaDecrypt(dataToDecrypt, contract.getPrivateKey());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String rsaEncrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String rsaDecrypt(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}