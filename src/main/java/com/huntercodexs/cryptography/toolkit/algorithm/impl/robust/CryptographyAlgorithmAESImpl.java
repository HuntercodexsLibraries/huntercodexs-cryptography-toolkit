package com.huntercodexs.cryptography.toolkit.algorithm.impl.robust;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.contract.robust.CryptographyContractRobustAES;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.*;
import static com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor.log;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm<Object> {

    CryptographyToolkitProcessor processor;

    @Override
    public String encrypt(Object contract, String dataToEncrypt) {
        this.processor = new CryptographyToolkitProcessor((CryptographyContractRobustAES) contract);
        return encryptAesRobust(dataToEncrypt, (CryptographyContractRobustAES) contract);
    }

    @Override
    public String decrypt(Object contract, String dataToDecrypt) {
        this.processor = new CryptographyToolkitProcessor((CryptographyContractRobustAES) contract);
        return decryptAesRobust(dataToDecrypt, (CryptographyContractRobustAES) contract);
    }

    private String encryptAesRobust(String dataToEncrypt, CryptographyContractRobustAES contract) {

        try {

            String ivSource = this.processor.getIvFromSourceRobust(dataToEncrypt, false, false);
            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            SecureRandom secureRandom = new SecureRandom();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            secureRandom.nextBytes(iv);

            String secretKey = this.processor.getSecretFromSourceRobust();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(AES_SECRET_KEY_INSTANCE_FACTORY);
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), contract.getSalt().getBytes(StandardCharsets.UTF_8), AES_ITERATION_COUNT_FOR_SPEC, AES_KEY_LENGTH_FOR_SPEC);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES_ALGORITHM_TYPE_FOR_SPEC);

            Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

            byte[] cipherText = cipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

            if (contract.getCryptographyIvSource().equals(CryptographyContractRobustAES.CryptographyIvSource.IV_FROM_AUTO_GENERATE)) {
                return this.processor.automaticGeneratorForEncrypt(ivSource, encryptedData);
            }

            return Base64.getEncoder().encodeToString(encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.encryptAesRobust: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String decryptAesRobust(String dataToDecrypt, CryptographyContractRobustAES contract) {

        try {

            String source = this.processor.getIvFromSourceRobust(dataToDecrypt, true, false);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;

            if (contract.getCryptographyIvSource().equals(CryptographyContractRobustAES.CryptographyIvSource.IV_FROM_AUTO_GENERATE)) {
                encSource = source.substring(16);
            }

            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] encryptedData = Base64.getDecoder().decode(encSource);
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            String secretKey = this.processor.getSecretFromSourceRobust();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(AES_SECRET_KEY_INSTANCE_FACTORY);
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), contract.getSalt().getBytes(StandardCharsets.UTF_8), AES_ITERATION_COUNT_FOR_SPEC, AES_KEY_LENGTH_FOR_SPEC);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES_ALGORITHM_TYPE_FOR_SPEC);

            Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

            byte[] cipherText = new byte[encryptedData.length - iv.length];
            System.arraycopy(encryptedData, iv.length, cipherText, 0, cipherText.length);

            byte[] decryptedText = cipher.doFinal(cipherText);
            return new String(decryptedText, StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.decryptAesRobust: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

}
