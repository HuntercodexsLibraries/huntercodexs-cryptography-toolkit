package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.ENCRYPTION_DES_SCHEME;

/**
 * 3DES (DESede)
 * */
public class CryptographyAlgorithm3DESImpl implements CryptographyAlgorithm {

    @Generated
    private static final Logger log = LoggerFactory.getLogger(CryptographyAlgorithm3DESImpl.class);

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        return encryptTripleDesAdvanced(dataToEncrypt, contract.getSecretKey());
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        return decryptTripleDesAdvanced(dataToDecrypt, contract.getSecretKey());
    }

    private String encryptTripleDesAdvanced(String dataToEncrypt, String secretKey) {
        try {

            byte[] arrayBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            KeySpec ks = new DESedeKeySpec(arrayBytes);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ENCRYPTION_DES_SCHEME);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_DES_SCHEME);
            SecretKey key = skf.generateSecret(ks);

            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = dataToEncrypt.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedText = cipher.doFinal(plainText);
            return new String(Base64.getEncoder().encode(encryptedText));

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithm3DESImpl.tripleDesEncrypt: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String decryptTripleDesAdvanced(String dataToDecrypt, String secretKey) {
        try {

            byte[] arrayBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            KeySpec ks = new DESedeKeySpec(arrayBytes);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ENCRYPTION_DES_SCHEME);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_DES_SCHEME);
            SecretKey key = skf.generateSecret(ks);

            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] encryptedText = Base64.getDecoder().decode(dataToDecrypt);
            byte[] plainText = cipher.doFinal(encryptedText);
            return new String(plainText);

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithm3DESImpl.tripleDesDecrypt: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }
}