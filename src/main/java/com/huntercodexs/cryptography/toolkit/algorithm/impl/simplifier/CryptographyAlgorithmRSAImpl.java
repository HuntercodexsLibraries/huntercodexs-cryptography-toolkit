package com.huntercodexs.cryptography.toolkit.algorithm.impl.simplifier;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.contract.simplifier.CryptographyContractSimplifierRSA;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.RSA_INSTANCE_TYPE_FOR_CIPHER;

/** 
 * RSA (Asymmetric) 
 * */
public class CryptographyAlgorithmRSAImpl implements CryptographyAlgorithm<Object> {

    @Override
    public String encrypt(Object contract, String dataToEncrypt) {
        try {
            return encryptRsaSimplifier(dataToEncrypt, ((CryptographyContractSimplifierRSA) contract).getPublicKey());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    @Override
    public String decrypt(Object contract, String dataToDecrypt) {
        try {
            return decryptRsaSimplifier(dataToDecrypt, ((CryptographyContractSimplifierRSA) contract).getPrivateKey());
        } catch (Exception e) {
            throw new CryptographyException(e.getMessage());
        }
    }

    private String encryptRsaSimplifier(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_INSTANCE_TYPE_FOR_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptRsaSimplifier(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_INSTANCE_TYPE_FOR_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}