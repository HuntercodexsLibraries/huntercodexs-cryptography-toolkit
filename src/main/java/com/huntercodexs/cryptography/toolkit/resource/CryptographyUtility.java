package com.huntercodexs.cryptography.toolkit.resource;

import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.*;

public abstract class CryptographyUtility {

    @Generated
    private static final Logger log = LoggerFactory.getLogger(CryptographyUtility.class);

    public static IvParameterSpec generateIvUtility() {
        byte[] iv = new byte[16]; // 16 bytes for AES
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static IvParameterSpec generateIvForDESUtility() {
        byte[] iv = new byte[8]; // DES/3DES use block of 8 bytes
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static SecretKey generateAESKeyUtility(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM_INSTANCE_NAME);
        keyGen.init(keySize); // 128, 192 ou 256
        return keyGen.generateKey();
    }

    public static SecretKey generateDESKeyUtility() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(DES_ALGORITHM_INSTANCE_NAME);
        keyGen.init(56);
        return keyGen.generateKey();
    }

    public static SecretKey generateTripleDESKeyUtility() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(TRIPLE_DES_ALGORITHM_INSTANCE_NAME);
        keyGen.init(168); // 112 or 168 bits
        return keyGen.generateKey();
    }

    public static KeyPair generateRSAKeyPairUtility(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM_INSTANCE_NAME);
        keyGen.initialize(keySize); // 2048 recommended
        return keyGen.generateKeyPair();
    }

    public static String loadSafetyFirstValue() {
        return Base64.getEncoder().encodeToString(":0x00101:".getBytes());
    }

    public static String loadSafetySecondValue() {
        return Base64.getEncoder().encodeToString(":0x11010:".getBytes());
    }

    public static String getSecretKeyFromProperties() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkitProcessor.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.secret-key.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyToolkitProcessor.getSecretKeyFromStaticProperties: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String getIvFromProperties() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkitProcessor.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.iv.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyToolkitProcessor.getIvFromStaticProperties: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }
}
