package com.huntercodexs.cryptography.toolkit.algorithm.impl.robust;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;

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
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm {

    CryptographyToolkitProcessor processor;

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        this.processor = new CryptographyToolkitProcessor(contract);
        return encryptAesRobust(dataToEncrypt, contract);
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        this.processor = new CryptographyToolkitProcessor(contract);
        return decryptAesRobust(dataToDecrypt, contract);
    }

    private String encryptAesRobust(String dataToEncrypt, CryptographyContract contract) {

        try {

            String ivSource = this.processor.getIvFromSource(dataToEncrypt, false, false);
            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            SecureRandom secureRandom = new SecureRandom();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            secureRandom.nextBytes(iv);

            String secretKey = this.processor.getSecretFromSource();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY);
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), contract.getSalt().getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES_ALG);

            Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

            byte[] cipherText = cipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

            if (contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                return this.processor.automaticGeneratorForEncrypt(ivSource, encryptedData);
            }

            return Base64.getEncoder().encodeToString(encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.encryptAesRobust: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String decryptAesRobust(String dataToDecrypt, CryptographyContract contract) {

        try {

            String source = this.processor.getIvFromSource(dataToDecrypt, true, false);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;

            if (contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                encSource = source.substring(16);
            }

            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] encryptedData = Base64.getDecoder().decode(encSource);
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            String secretKey = this.processor.getSecretFromSource();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY);
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), contract.getSalt().getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES_ALG);

            Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
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
