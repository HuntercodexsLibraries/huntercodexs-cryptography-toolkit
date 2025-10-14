package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor;
import com.huntercodexs.cryptography.toolkit.contract.CryptographyContract;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.*;
import static com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor.*;
import static com.huntercodexs.cryptography.toolkit.contract.CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE;
import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptographyToolkit {

    @Generated
    private static final Logger log = LoggerFactory.getLogger(CryptographyToolkit.class);

    CryptographyContract contract;
    CryptographyToolkitProcessor processor;

    public CryptographyToolkit(CryptographyContract contract) {
        this.contract = contract;
        this.processor = new CryptographyToolkitProcessor(this.contract);
    }

    public static String encryptAes256CbcRobust(CryptographyContract contract, String dataToEncrypt) {

        try {

            String ivSource = getIvFromStaticSource(contract, dataToEncrypt, false);
            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            SecureRandom secureRandom = new SecureRandom();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            secureRandom.nextBytes(iv);

            String secretKey = getSecretFromStaticSource(contract);

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
                return automaticGeneratorForStaticEncrypt(ivSource, encryptedData);
            }

            return Base64.getEncoder().encodeToString(encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256Static: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String decryptAes256CbcRobust(CryptographyContract contract, String dataToDecrypt) {

        try {
            String source = getIvFromStaticSource(contract, dataToDecrypt, true);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;

            if (contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                encSource = source.substring(16);
            }

            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] encryptedData = Base64.getDecoder().decode(encSource);
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            String secretKey = getSecretFromStaticSource(contract);

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
            log.error("Fail in CryptographyToolkit.decryptAesCbc256Static: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String encryptAes256CbcAutomatic(String dataToEncrypt) {

        try {

            String ivSource = generateRandomKey();
            String secretKey = generateRandomKey();

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivSource.getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));

            return automaticGeneratorForRobustEncrypt(ivSource, secretKey, encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256DynamicFULL_AUTO_GENERATED: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String decryptAes256CbcAutomatic(String dataToDecrypt) {

        try {

            String decipher = automaticGeneratorForRobustDecrypt(dataToDecrypt);
            String ivSource = decipher.substring(0, 16);
            String secretKey = decipher.substring(16, 32);
            String encSource = decipher.substring(32);

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivSource.getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(encSource.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.decryptAesCbc256DynamicFULL_AUTO_GENERATED: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String encryptAes256CbcDynamicBasic(String dataToEncrypt) {
        try {

            String ivSource = this.processor.getIvFromSource(dataToEncrypt, false, true);
            String secretKey = this.processor.getSecretFromSource();

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivSource.getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));

            if (this.contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                return this.processor.automaticGeneratorForDynamicBasicEncrypt(ivSource, encryptedData);
            }

            return new String(Base64.getEncoder().encode(encryptedData));

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAes256CbcDynamicBasic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String decryptAes256CbcDynamicBasic(String dataToDecrypt) {
        try {
            String source = this.processor.getIvFromSource(dataToDecrypt, true, true);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;
            String secretKey = this.processor.getSecretFromSource();

            if (this.contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                encSource = source.substring(16);
            }

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivSource.getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(encSource.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.decryptAes256CbcDynamicBasic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

}
