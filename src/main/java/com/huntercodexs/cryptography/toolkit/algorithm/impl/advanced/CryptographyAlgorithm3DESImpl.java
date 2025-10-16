package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.contract.advanced.CryptographyContractAdvanced3DES;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Logger;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.TRIPLE_DES_SECRET_KEY_INSTANCE_FACTORY;

/**
 * 3DES (DESede)
 * */
public class CryptographyAlgorithm3DESImpl implements CryptographyAlgorithm<Object> {

    private static final Logger log = Logger.getLogger(CryptographyAlgorithm3DESImpl.class.getName());

    @Override
    public String encrypt(Object contract, String dataToEncrypt) {
        return encryptTripleDesAdvanced(dataToEncrypt, ((CryptographyContractAdvanced3DES) contract).getSecretKey());
    }

    @Override
    public String decrypt(Object contract, String dataToDecrypt) {
        return decryptTripleDesAdvanced(dataToDecrypt, ((CryptographyContractAdvanced3DES) contract).getSecretKey());
    }

    private String encryptTripleDesAdvanced(String dataToEncrypt, String secretKey) {
        try {

            byte[] arrayBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            KeySpec ks = new DESedeKeySpec(arrayBytes);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(TRIPLE_DES_SECRET_KEY_INSTANCE_FACTORY);
            Cipher cipher = Cipher.getInstance(TRIPLE_DES_SECRET_KEY_INSTANCE_FACTORY);
            SecretKey key = skf.generateSecret(ks);

            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = dataToEncrypt.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedText = cipher.doFinal(plainText);
            return new String(Base64.getEncoder().encode(encryptedText));

        } catch (Exception e) {
            log.severe("Fail in CryptographyAlgorithm3DESImpl.encryptTripleDesAdvanced: " + e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String decryptTripleDesAdvanced(String dataToDecrypt, String secretKey) {
        try {

            byte[] arrayBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            KeySpec ks = new DESedeKeySpec(arrayBytes);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(TRIPLE_DES_SECRET_KEY_INSTANCE_FACTORY);
            Cipher cipher = Cipher.getInstance(TRIPLE_DES_SECRET_KEY_INSTANCE_FACTORY);
            SecretKey key = skf.generateSecret(ks);

            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] encryptedText = Base64.getDecoder().decode(dataToDecrypt);
            byte[] plainText = cipher.doFinal(encryptedText);
            return new String(plainText);

        } catch (Exception e) {
            log.severe("Fail in CryptographyAlgorithm3DESImpl.decryptTripleDesAdvanced: " + e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

}