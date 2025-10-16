package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.contract.advanced.CryptographyContractAdvancedAES;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.logging.Logger;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_ALGORITHM_TYPE_FOR_SPEC;
import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_INSTANCE_TYPE_FOR_CIPHER;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm<Object> {

    private static final Logger log = Logger.getLogger(CryptographyAlgorithmAESImpl.class.getName());

    @Override
    public String encrypt(Object contract, String dataToEncrypt) {

        return encryptAesAdvanced(
                dataToEncrypt,
                ((CryptographyContractAdvancedAES) contract).getIv().getBytes(),
                ((CryptographyContractAdvancedAES) contract).getSecretKey());
    }

    @Override
    public String decrypt(Object contract, String dataToDecrypt) {
        return decryptAesAdvanced(
                dataToDecrypt,
                ((CryptographyContractAdvancedAES) contract).getIv().getBytes(),
                ((CryptographyContractAdvancedAES) contract).getSecretKey());
    }

    private static String encryptAesAdvanced(String dataToEncrypt, byte[] ivParameter, String secretKey) {
        try {

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES_ALGORITHM_TYPE_FOR_SPEC);
            AlgorithmParameterSpec param = new IvParameterSpec(ivParameter);
            Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] bytes = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));
            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            log.severe("Fail in CryptographyAlgorithmAESImpl.encryptAesAdvanced: " + e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private static String decryptAesAdvanced(String dataToDecrypt, byte[] ivParameter, String secretKey) {
        try {

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES_ALGORITHM_TYPE_FOR_SPEC);
            AlgorithmParameterSpec param = new IvParameterSpec(ivParameter);
            Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(dataToDecrypt.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.severe("Fail in CryptographyAlgorithmAESImpl.decryptAesAdvanced: " + e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

}
