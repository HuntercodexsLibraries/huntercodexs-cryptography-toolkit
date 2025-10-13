package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.UUID;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.*;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyContract.CryptographySecretKeySource.SECRET_FROM_APPLICATION_PROPERTIES;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyContract.CryptographySecretKeySource.SECRET_FROM_PARAMETER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;

public class CryptographyToolkit {

    @Generated
    private static final Logger log = LoggerFactory.getLogger(CryptographyToolkit.class);

    private static final String SECRET_CONCAT_VALUE = "/x0t0x00001p#";
    private static final String REPLACE_VALUE_SAFETY_FIRST = loadSafetyValueFirst();
    private static final String REPLACE_VALUE_SAFETY_SECOND = loadSafetyValueSecond();

    CryptographyContract contract;

    public CryptographyToolkit(CryptographyContract contract) {
        this.contract = contract;
    }

    public String encrypt3desEde(String dataToEncrypt, String secretKey) {
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
            log.error("Fail in CryptographyToolkit.encrypt3desEde: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String decrypt3DesEde(String dataToDecrypt, String secretKey) {
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
            log.error("Fail in CryptographyToolkit.decrypt3DesEde: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String encryptAesCbc256BASIC(String dataToEncrypt) {
        try {

            Key keySpec = new SecretKeySpec(this.contract.getSecretKey().getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(this.contract.getIv().getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] bytes = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));
            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256BASIC: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String decryptAesCbc256BASIC(String dataToDecrypt) {
        try {

            Key keySpec = new SecretKeySpec(this.contract.getSecretKey().getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(this.contract.getIv().getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(dataToDecrypt.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.decryptAesCbc256BASIC: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String encryptAesCbc256DynamicBASIC(String dataToEncrypt) {
        try {

            String ivSource = ivSource(dataToEncrypt, false, true);
            String secretKey = secretSource();

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivSource.getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));

            if (this.contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                return autoGeneratedEncryptDynamicBASIC(ivSource, encryptedData);
            }

            return new String(Base64.getEncoder().encode(encryptedData));

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256DynamicBASIC: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String decryptAesCbc256DynamicBASIC(String dataToDecrypt) {
        try {
            String source = ivSource(dataToDecrypt, true, true);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;
            String secretKey = secretSource();

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
            log.error("Fail in CryptographyToolkit.decryptAesCbc256DynamicBASIC: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String encryptAesCbc256DynamicFULL_AUTO_GENERATED(String dataToEncrypt) {

        try {

            String ivSource = generateRandomKey();
            String secretKey = generateRandomKey();

            Key keySpec = new SecretKeySpec(secretKey.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivSource.getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));

            return autoGeneratedEncryptDynamicFULL_AUTO_GENERATED(ivSource, secretKey, encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256DynamicFULL_AUTO_GENERATED: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String decryptAesCbc256DynamicFULL_AUTO_GENERATED(String dataToDecrypt) {

        try {

            String decipher = autoGeneratedDecryptDynamicFULL_AUTO_GENERATED(dataToDecrypt);
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

    public String encryptAesCbc256STRONGER(String dataToEncrypt) {

        try {

            String ivSource = ivSource(dataToEncrypt, false, false);
            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            SecureRandom secureRandom = new SecureRandom();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            secureRandom.nextBytes(iv);

            String secretKey = secretSource();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY);
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), this.contract.getSalt().getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES_ALG);

            Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

            byte[] cipherText = cipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

            if (this.contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                return autoGeneratedEncrypt(ivSource, encryptedData);
            }

            return Base64.getEncoder().encodeToString(encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256STRONGER: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public String decryptAesCbc256STRONGER(String dataToDecrypt) {

        try {

            String source = ivSource(dataToDecrypt, true, false);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;

            if (this.contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                encSource = source.substring(16);
            }

            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] encryptedData = Base64.getDecoder().decode(encSource);
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            String secretKey = secretSource();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY);
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), this.contract.getSalt().getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES_ALG);

            Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

            byte[] cipherText = new byte[encryptedData.length - iv.length];
            System.arraycopy(encryptedData, iv.length, cipherText, 0, cipherText.length);

            byte[] decryptedText = cipher.doFinal(cipherText);
            return new String(decryptedText, StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.decryptAesCbc256STRONGER: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String encryptAesCbc256StaticSTRONGER(CryptographyContract contract, String dataToEncrypt) {

        try {

            String ivSource = ivSourceStatic(contract, dataToEncrypt, false);
            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            SecureRandom secureRandom = new SecureRandom();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            secureRandom.nextBytes(iv);

            String secretKey = secretSourceStatic(contract);

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
                return autoGeneratedEncryptStatic(ivSource, encryptedData);
            }

            return Base64.getEncoder().encodeToString(encryptedData);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAesCbc256Static: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String decryptAesCbc256StaticSTRONGER(CryptographyContract contract, String dataToDecrypt) {

        try {
            String source = ivSourceStatic(contract, dataToDecrypt, true);
            String ivSource = source.substring(0, 16);
            String encSource = dataToDecrypt;

            if (contract.getCryptographyIvSource().equals(IV_FROM_AUTO_GENERATE)) {
                encSource = source.substring(16);
            }

            byte[] iv = ivSource.getBytes(StandardCharsets.UTF_8);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] encryptedData = Base64.getDecoder().decode(encSource);
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            String secretKey = secretSourceStatic(contract);

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

    private String secretSource() {

        if (this.contract.getCryptographySecretKeySource().equals(SECRET_FROM_PARAMETER)) {
            return this.contract.getSecretKey();

        } else if (this.contract.getCryptographySecretKeySource().equals(SECRET_FROM_APPLICATION_PROPERTIES)) {
            return getSecretKeyParameter();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: Secret Spec (CryptographySecretKeySource)");
    }

    private static String secretSourceStatic(CryptographyContract contract) {

        if (contract.getCryptographySecretKeySource().equals(SECRET_FROM_PARAMETER)) {
            return contract.getSecretKey();

        } else if (contract.getCryptographySecretKeySource().equals(SECRET_FROM_APPLICATION_PROPERTIES)) {
            return getSecretKeyParameterStatic();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: Secret Spec (CryptographySecretKeySource)");
    }

    private String ivSource(String data, boolean isDecrypt, boolean isBasic) {
        if (this.contract.getCryptographyIvSource() == CryptographyContract.CryptographyIvSource.IV_FROM_PARAMETER) {
            return this.contract.getIv();
        } else if (this.contract.getCryptographyIvSource() == CryptographyContract.CryptographyIvSource.IV_FROM_APPLICATION_PROPERTIES) {
            return getIvParameter();
        } else if (this.contract.getCryptographyIvSource() == CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE) {
            if (isDecrypt && !isBasic) {
                return autoGeneratedDecrypt(data);
            } else if (isDecrypt) {
                return data;
            }
            return generateRandomKey();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: IV Parameter Spec (CryptographyIvSource)");
    }

    private static String generateRandomKey() {
        return UUID.randomUUID().toString().toUpperCase().replaceAll("-", "").substring(0, 16);
    }

    private static String ivSourceStatic(CryptographyContract contract, String data, boolean isDecrypt) {
        if (contract.getCryptographyIvSource() == CryptographyContract.CryptographyIvSource.IV_FROM_PARAMETER) {
            return contract.getIv();
        } else if (contract.getCryptographyIvSource() == CryptographyContract.CryptographyIvSource.IV_FROM_APPLICATION_PROPERTIES) {
            return getIvParameterStatic();
        } else if (contract.getCryptographyIvSource() == CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE) {
            if (isDecrypt) {
                return autoGeneratedDecryptStatic(data);
            }
            return UUID.randomUUID().toString().toUpperCase().replaceAll("-", "").substring(0, 16);
        }

        throw new CryptographyException("Cryptography Toolkit Fail: IV Parameter Spec (CryptographyIvSource)");
    }

    private String getSecretKeyParameter() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkit.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.secret-key.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyToolkit.getSecretKeyParameter: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private static String getSecretKeyParameterStatic() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkit.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.secret-key.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyToolkit.getSecretKeyParameterStatic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String getIvParameter() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkit.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.iv.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyToolkit.getIvParameter: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private static String getIvParameterStatic() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkit.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.iv.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyToolkit.getIvParameterStatic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String autoGeneratedEncrypt(String ivSource, byte[] encryptedData) {
        int size = Base64.getEncoder().encodeToString(encryptedData).length();
        int half = size / 2;

        String encP1 = Base64.getEncoder().encodeToString(encryptedData).substring(0, half);
        String encP2 = Base64.getEncoder().encodeToString(encryptedData).substring(half)
                .replaceAll("=$", REPLACE_VALUE_SAFETY_FIRST).concat(SECRET_CONCAT_VALUE);

        return ivSource.substring(0, 8)
                .concat(encP2)
                .concat(ivSource.substring(8, 16))
                .concat(encP1);
    }

    private String autoGeneratedEncryptDynamicBASIC(String ivSource, byte[] encryptedData) {
        return ivSource+Base64.getEncoder().encodeToString(encryptedData);
    }

    private static String autoGeneratedEncryptStatic(String ivSource, byte[] encryptedData) {
        int size = Base64.getEncoder().encodeToString(encryptedData).length();
        int half = size / 2;

        String encP1 = Base64.getEncoder().encodeToString(encryptedData).substring(0, half);
        String encP2 = Base64.getEncoder().encodeToString(encryptedData).substring(half)
                .replaceAll("=$", REPLACE_VALUE_SAFETY_FIRST).concat(SECRET_CONCAT_VALUE);

        return ivSource.substring(0, 8)
                .concat(encP2)
                .concat(ivSource.substring(8, 16))
                .concat(encP1);
    }

    private String autoGeneratedDecrypt(String dataToDecrypt) {

        String[] parts = dataToDecrypt.replaceAll(SECRET_CONCAT_VALUE, "=").split("=");

        String ivP1 = parts[0].substring(0 ,8);
        String ivP2 = parts[1].substring(0, 8);

        String encP1 = parts[1].substring(8);
        String encP2 = parts[0].substring(8);

        return ivP1+ivP2+encP1+encP2.replaceAll(REPLACE_VALUE_SAFETY_FIRST, "=");
    }

    private static String autoGeneratedDecryptStatic(String dataToDecrypt) {

        String[] parts = dataToDecrypt.replaceAll(SECRET_CONCAT_VALUE, "=").split("=");

        String ivP1 = parts[0].substring(0 ,8);
        String ivP2 = parts[1].substring(0, 8);

        String encP1 = parts[1].substring(8);
        String encP2 = parts[0].substring(8);

        return ivP1+ivP2+encP1+encP2.replaceAll(REPLACE_VALUE_SAFETY_FIRST, "=");
    }

    private static String autoGeneratedEncryptDynamicFULL_AUTO_GENERATED(String ivSource, String secretKey, byte[] encryptedData) {
        int size = Base64.getEncoder().encodeToString(encryptedData).length();
        int half = size / 2;

        String encP1 = Base64.getEncoder().encodeToString(encryptedData).substring(0, half);
        String encP2 = Base64.getEncoder().encodeToString(encryptedData).substring(half)
                .replaceAll("==$", REPLACE_VALUE_SAFETY_FIRST + REPLACE_VALUE_SAFETY_SECOND)
                .replaceAll("=$", REPLACE_VALUE_SAFETY_FIRST)
                .concat(SECRET_CONCAT_VALUE);

        return Base64.getEncoder().encodeToString(ivSource.substring(0, 8).getBytes())
                .concat(Base64.getEncoder().encodeToString(secretKey.substring(8, 16).getBytes()))
                .concat(encP2)
                .concat(Base64.getEncoder().encodeToString(ivSource.substring(8, 16).getBytes()))
                .concat(Base64.getEncoder().encodeToString(secretKey.substring(0, 8).getBytes()))
                .concat(encP1).replaceAll("=", "\\$");
    }

    private static String autoGeneratedDecryptDynamicFULL_AUTO_GENERATED(String dataToDecrypt) {
        String[] parts = dataToDecrypt.replaceAll(SECRET_CONCAT_VALUE, "=").split("=");

        String part0 = parts[0].replaceAll("\\$", "=");
        String part1 = parts[1].replaceAll("\\$", "=");

        String ivP1 = new String(Base64.getDecoder().decode(part0.substring(0, 12)));
        String ivP2 = new String(Base64.getDecoder().decode(part1.substring(0, 12)));

        String secP1 = new String(Base64.getDecoder().decode(part0.substring(12, 24)));
        String secP2 = new String(Base64.getDecoder().decode(part1.substring(12, 24)));

        String encP1 = part1.substring(24);
        String encP2 = part0.substring(24);

        return ivP1+ivP2+secP2+secP1+encP1+encP2
                .replaceAll(REPLACE_VALUE_SAFETY_SECOND, "=")
                .replaceAll(REPLACE_VALUE_SAFETY_FIRST, "=");
    }

    private static String loadSafetyValueFirst() {
        return Base64.getEncoder().encodeToString(":0x00101:".getBytes());
    }

    private static String loadSafetyValueSecond() {
        return Base64.getEncoder().encodeToString(":0x11010:".getBytes());
    }

    /*
     * Old Version
     */

    public static final String AES_CBC = "AES/CBC/PKCS5Padding";
    public static final String IV_PARAMETER_SPEC = getIvParameterStatic();

    private static final String AES = "AES";

    public static String encryptAES(String text, String key) {
        return encryptAESPrivate(text, IV_PARAMETER_SPEC.getBytes(), key);
    }

    private static String encryptAESPrivate(String text, byte[] ivParameter, String key) {
        try {

            Key keySpec = new SecretKeySpec(key.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivParameter);
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] bytes = cipher.doFinal(text.getBytes(UTF_8));
            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.encryptAES: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String decryptAES(String text, String key) {
        if (isNull(text)) {
            log.warn("Text is null in CryptographyToolkit.decryptAES");
            return null;
        }
        return decryptAESPrivate(text, IV_PARAMETER_SPEC.getBytes(), key);
    }

    private static String decryptAESPrivate(String text, byte[] ivParameter, String key) {
        try {

            Key keySpec = new SecretKeySpec(key.getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(ivParameter);
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(text.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.error("Fail in CryptographyToolkit.decryptAES: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

}
