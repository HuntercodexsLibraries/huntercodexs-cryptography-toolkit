package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DataBuilder {

    public static final String SALT_TEST = "1";
    public static final String IV_TEST = "F1F2F3F4F5F6F7F8";
    public static final String SECRET_KEY_TEST = "F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8";

    public CryptographyContract resourceFromParameters() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(IV_TEST);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_PARAMETER);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromParametersAndApplicationProperties() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_APPLICATION_PROPERTIES);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromParametersAndAutoGenerate() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromApplicationPropertiesAndParameter() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(null);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(IV_TEST);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_APPLICATION_PROPERTIES);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_PARAMETER);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromApplicationProperties() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(null);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_APPLICATION_PROPERTIES);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_APPLICATION_PROPERTIES);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromApplicationPropertiesAndAutoGenerate() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(null);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_APPLICATION_PROPERTIES);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_AUTO_GENERATE);
        return cryptographyContract;
    }

    public static CryptographyContract contractForAesAnd3Des() {
        CryptographyContract contract = new CryptographyContract();
        contract.setSecretKey(SECRET_KEY_TEST);
        contract.setSalt(SALT_TEST);
        contract.setIv(IV_TEST);
        return contract;
    }

    public static CryptographyContract contractForAesAnd3DesSimple(SecretKey secretKey, IvParameterSpec iv) {
        CryptographyContract contract = new CryptographyContract();
        contract.setCryptoSecretKey(secretKey);
        contract.setCryptoSpecIv(iv);
        return contract;
    }

    public static CryptographyContract contractForRSA(PublicKey publicKey, PrivateKey privateKey) {
        CryptographyContract contract = new CryptographyContract();
        contract.setPublicKey(publicKey);
        contract.setPrivateKey(privateKey);
        return contract;
    }

    public static CryptographyContract contractForAesAnd3DesFromParameters() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(IV_TEST);
        cryptographyContract.setCryptographySecretKeySource(CryptographyContract.CryptographySecretKeySource.SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(CryptographyContract.CryptographyIvSource.IV_FROM_PARAMETER);
        return cryptographyContract;
    }

}
