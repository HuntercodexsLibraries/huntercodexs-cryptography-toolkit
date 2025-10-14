package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES;
import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_CBC;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm {

    @Generated
    private static final Logger log = LoggerFactory.getLogger(CryptographyAlgorithmAESImpl.class);

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        return encryptAesAdvanced(dataToEncrypt, contract.getIv().getBytes(), contract.getSecretKey());
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        return decryptAesAdvanced(dataToDecrypt, contract.getIv().getBytes(), contract.getSecretKey());
    }

    private static String encryptAesAdvanced(String dataToEncrypt, byte[] ivParameter, String secretKey) {
        try {

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivParameter);
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] bytes = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));
            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.aesEncrypt: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private static String decryptAesAdvanced(String dataToDecrypt, byte[] ivParameter, String secretKey) {
        try {

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivParameter);
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(dataToDecrypt.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.aesDecrypt: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }
}
