package com.huntercodexs.cryptography.toolkit.process;

import com.huntercodexs.cryptography.toolkit.contract.CryptographyContract;
import com.huntercodexs.cryptography.toolkit.contract.robust.CryptographyContractRobustAES;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.UUID;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.*;
import static com.huntercodexs.cryptography.toolkit.enumerator.CryptographyIvSource.*;
import static com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource.SECRET_FROM_APPLICATION_PROPERTIES;
import static com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource.SECRET_FROM_PARAMETER;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility.getIvFromProperties;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility.getSecretKeyFromProperties;

public class CryptographyToolkitProcessor {

    @Generated
    public static final Logger log = LoggerFactory.getLogger(CryptographyToolkitProcessor.class);

    CryptographyContract contract;
    CryptographyContractRobustAES contractRobustAES;

    public CryptographyToolkitProcessor(CryptographyContract contract) {
        this.contract = contract;
    }

    public CryptographyToolkitProcessor(CryptographyContractRobustAES contract) {
        this.contractRobustAES = contract;
    }

    public static String generateRandomKey() {
        return UUID.randomUUID().toString().toUpperCase().replaceAll("-", "").substring(0, 16);
    }

    public static String getSecretFromStaticSource(CryptographyContract contract) {

        if (contract.getCryptographySecretKeySource().equals(SECRET_FROM_PARAMETER)) {
            return contract.getSecretKey();

        } else if (contract.getCryptographySecretKeySource().equals(SECRET_FROM_APPLICATION_PROPERTIES)) {
            return getSecretKeyFromProperties();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: Secret Spec (getSecretFromStaticSource)");
    }

    public static String getIvFromStaticSource(CryptographyContract contract, String data, boolean isDecrypt) {
        if (contract.getCryptographyIvSource() == IV_FROM_PARAMETER) {
            return contract.getIv();
        } else if (contract.getCryptographyIvSource() == IV_FROM_APPLICATION_PROPERTIES) {
            return getIvFromProperties();
        } else if (contract.getCryptographyIvSource() == IV_FROM_AUTO_GENERATE) {
            if (isDecrypt) {
                return automaticGeneratorForStaticDecrypt(data);
            }
            return UUID.randomUUID().toString().toUpperCase().replaceAll("-", "").substring(0, 16);
        }

        throw new CryptographyException("Cryptography Toolkit Fail: IV Parameter Spec (getIvFromStaticSource)");
    }

    public static String automaticGeneratorForStaticEncrypt(String ivSource, byte[] encryptedData) {
        int size = Base64.getEncoder().encodeToString(encryptedData).length();
        int half = size / 2;

        String encP1 = Base64.getEncoder().encodeToString(encryptedData).substring(0, half);
        String encP2 = Base64.getEncoder().encodeToString(encryptedData).substring(half)
                .replaceAll("=$", SAFETY_FIRST_VALUE).concat(SECRET_CONCAT_VALUE);

        return ivSource.substring(0, 8)
                .concat(encP2)
                .concat(ivSource.substring(8, 16))
                .concat(encP1);
    }

    public static String automaticGeneratorForStaticDecrypt(String dataToDecrypt) {

        String[] parts = dataToDecrypt.replaceAll(SECRET_CONCAT_VALUE, "=").split("=");

        String ivP1 = parts[0].substring(0 ,8);
        String ivP2 = parts[1].substring(0, 8);

        String encP1 = parts[1].substring(8);
        String encP2 = parts[0].substring(8);

        return ivP1+ivP2+encP1+encP2.replaceAll(SAFETY_FIRST_VALUE, "=");
    }

    public static String automaticGeneratorForRobustEncrypt(String ivSource, String secretKey, byte[] encryptedData) {
        int size = Base64.getEncoder().encodeToString(encryptedData).length();
        int half = size / 2;

        String encP1 = Base64.getEncoder().encodeToString(encryptedData).substring(0, half);
        String encP2 = Base64.getEncoder().encodeToString(encryptedData).substring(half)
                .replaceAll("==$", SAFETY_FIRST_VALUE + SAFETY_SECOND_VALUE)
                .replaceAll("=$", SAFETY_FIRST_VALUE)
                .concat(SECRET_CONCAT_VALUE);

        return Base64.getEncoder().encodeToString(ivSource.substring(0, 8).getBytes())
                .concat(Base64.getEncoder().encodeToString(secretKey.substring(8, 16).getBytes()))
                .concat(encP2)
                .concat(Base64.getEncoder().encodeToString(ivSource.substring(8, 16).getBytes()))
                .concat(Base64.getEncoder().encodeToString(secretKey.substring(0, 8).getBytes()))
                .concat(encP1).replaceAll("=", "\\$");
    }

    public static String automaticGeneratorForRobustDecrypt(String dataToDecrypt) {
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
                .replaceAll(SAFETY_SECOND_VALUE, "=")
                .replaceAll(SAFETY_FIRST_VALUE, "=");
    }

    public String getSecretFromSource() {

        if (this.contract.getCryptographySecretKeySource().equals(SECRET_FROM_PARAMETER)) {
            return this.contract.getSecretKey();

        } else if (this.contract.getCryptographySecretKeySource().equals(SECRET_FROM_APPLICATION_PROPERTIES)) {
            return getSecretKeyFromProperties();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: Secret Spec (getSecretFromSource)");
    }

    public String getIvFromSource(String data, boolean isDecrypt, boolean isBasic) {
        if (this.contract.getCryptographyIvSource() == IV_FROM_PARAMETER) {
            return this.contract.getIv();
        } else if (this.contract.getCryptographyIvSource() == IV_FROM_APPLICATION_PROPERTIES) {
            return getIvFromProperties();
        } else if (this.contract.getCryptographyIvSource() == IV_FROM_AUTO_GENERATE) {
            if (isDecrypt && !isBasic) {
                return automaticGeneratorForDecrypt(data);
            } else if (isDecrypt) {
                return data;
            }
            return generateRandomKey();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: IV Parameter Spec (getIvFromSource)");
    }

    public String getSecretFromSourceRobust() {

        if (this.contractRobustAES.getCryptographySecretKeySource().equals(SECRET_FROM_PARAMETER)) {
            return this.contractRobustAES.getSecretKey();

        } else if (this.contractRobustAES.getCryptographySecretKeySource().equals(SECRET_FROM_APPLICATION_PROPERTIES)) {
            return getSecretKeyFromProperties();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: Secret Spec (getSecretFromSource)");
    }

    public String getIvFromSourceRobust(String data, boolean isDecrypt, boolean isBasic) {
        if (this.contractRobustAES.getCryptographyIvSource() == IV_FROM_PARAMETER) {
            return this.contractRobustAES.getIv();
        } else if (this.contractRobustAES.getCryptographyIvSource() == IV_FROM_APPLICATION_PROPERTIES) {
            return getIvFromProperties();
        } else if (this.contractRobustAES.getCryptographyIvSource() == IV_FROM_AUTO_GENERATE) {
            if (isDecrypt && !isBasic) {
                return automaticGeneratorForDecrypt(data);
            } else if (isDecrypt) {
                return data;
            }
            return generateRandomKey();
        }

        throw new CryptographyException("Cryptography Toolkit Fail: IV Parameter Spec (getIvFromSource)");
    }

    public String automaticGeneratorForEncrypt(String ivSource, byte[] encryptedData) {
        int size = Base64.getEncoder().encodeToString(encryptedData).length();
        int half = size / 2;

        String encP1 = Base64.getEncoder().encodeToString(encryptedData).substring(0, half);
        String encP2 = Base64.getEncoder().encodeToString(encryptedData).substring(half)
                .replaceAll("=$", SAFETY_FIRST_VALUE).concat(SECRET_CONCAT_VALUE);

        return ivSource.substring(0, 8)
                .concat(encP2)
                .concat(ivSource.substring(8, 16))
                .concat(encP1);
    }

    public String automaticGeneratorForDynamicBasicEncrypt(String ivSource, byte[] encryptedData) {
        return ivSource+Base64.getEncoder().encodeToString(encryptedData);
    }

    public String automaticGeneratorForDecrypt(String dataToDecrypt) {

        String[] parts = dataToDecrypt.replaceAll(SECRET_CONCAT_VALUE, "=").split("=");

        String ivP1 = parts[0].substring(0 ,8);
        String ivP2 = parts[1].substring(0, 8);

        String encP1 = parts[1].substring(8);
        String encP2 = parts[0].substring(8);

        return ivP1+ivP2+encP1+encP2.replaceAll(SAFETY_FIRST_VALUE, "=");
    }

}
