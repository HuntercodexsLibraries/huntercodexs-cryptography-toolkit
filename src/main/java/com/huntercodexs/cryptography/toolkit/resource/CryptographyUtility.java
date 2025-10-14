package com.huntercodexs.cryptography.toolkit.resource;

import com.huntercodexs.cryptography.toolkit.CryptographyToolkit;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
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
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize); // 128, 192 ou 256
        return keyGen.generateKey();
    }

    public static SecretKey generateDESKeyUtility() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        return keyGen.generateKey();
    }

    public static SecretKey generateTripleDESKeyUtility() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(168); // 112 or 168 bits
        return keyGen.generateKey();
    }

    public static KeyPair generateRSAKeyPairUtility(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize); // 2048 recommended
        return keyGen.generateKeyPair();
    }

    public static String getIvParameterUtility() {
        try {
            Properties prop = new Properties();
            prop.load(CryptographyToolkit.class.getClassLoader().getResourceAsStream("application.properties"));
            return prop.getProperty("cryptography-toolkit.iv.parameter");
        } catch (IOException e) {
            log.error("Fail in CryptographyUtility.getIvParameterUtility: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    public static String loadSafetyFirstValue() {
        return Base64.getEncoder().encodeToString(":0x00101:".getBytes());
    }

    public static String loadSafetySecondValue() {
        return Base64.getEncoder().encodeToString(":0x11010:".getBytes());
    }
}
