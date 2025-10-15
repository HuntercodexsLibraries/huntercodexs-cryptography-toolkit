package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.contract.CryptographyContract;
import com.huntercodexs.cryptography.toolkit.contract.advanced.CryptographyContractAdvanced3DES;
import com.huntercodexs.cryptography.toolkit.contract.advanced.CryptographyContractAdvancedAES;
import com.huntercodexs.cryptography.toolkit.contract.basic.CryptographyContractBasicAES;
import com.huntercodexs.cryptography.toolkit.contract.robust.CryptographyContractRobustAES;
import com.huntercodexs.cryptography.toolkit.contract.simplifier.CryptographyContractSimplifier3DES;
import com.huntercodexs.cryptography.toolkit.contract.simplifier.CryptographyContractSimplifierAES;
import com.huntercodexs.cryptography.toolkit.contract.simplifier.CryptographyContractSimplifierDES;
import com.huntercodexs.cryptography.toolkit.contract.simplifier.CryptographyContractSimplifierRSA;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.huntercodexs.cryptography.toolkit.enumerator.CryptographyIvSource.*;
import static com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource.SECRET_FROM_APPLICATION_PROPERTIES;
import static com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource.SECRET_FROM_PARAMETER;

public class DataBuilder {

    public static final String SALT_TEST = "1";
    public static final String IV_TEST = "F1F2F3F4F5F6F7F8";
    public static final String SECRET_KEY_TEST = "F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8";

    public CryptographyContract resourceFromParameters() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(IV_TEST);
        cryptographyContract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(IV_FROM_PARAMETER);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromParametersAndApplicationProperties() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(IV_FROM_APPLICATION_PROPERTIES);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromParametersAndAutoGenerate() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(SECRET_KEY_TEST);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        cryptographyContract.setCryptographyIvSource(IV_FROM_AUTO_GENERATE);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromApplicationPropertiesAndParameter() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(null);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(IV_TEST);
        cryptographyContract.setCryptographySecretKeySource(SECRET_FROM_APPLICATION_PROPERTIES);
        cryptographyContract.setCryptographyIvSource(IV_FROM_PARAMETER);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromApplicationProperties() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(null);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(SECRET_FROM_APPLICATION_PROPERTIES);
        cryptographyContract.setCryptographyIvSource(IV_FROM_APPLICATION_PROPERTIES);
        return cryptographyContract;
    }

    public CryptographyContract resourceFromApplicationPropertiesAndAutoGenerate() {
        CryptographyContract cryptographyContract = new CryptographyContract();
        cryptographyContract.setSecretKey(null);
        cryptographyContract.setSalt(SALT_TEST);
        cryptographyContract.setIv(null);
        cryptographyContract.setCryptographySecretKeySource(SECRET_FROM_APPLICATION_PROPERTIES);
        cryptographyContract.setCryptographyIvSource(IV_FROM_AUTO_GENERATE);
        return cryptographyContract;
    }

    public static CryptographyContractAdvanced3DES argsForContractAdvanced3DES() {
        CryptographyContractAdvanced3DES contract = new CryptographyContractAdvanced3DES();
        contract.setSecretKey(SECRET_KEY_TEST);
        contract.setSalt(SALT_TEST);
        contract.setIv(IV_TEST);
        contract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        contract.setCryptographyIvSource(IV_FROM_PARAMETER);
        return contract;
    }

    public static CryptographyContractAdvancedAES argsForContractAdvancedAES() {
        CryptographyContractAdvancedAES contract = new CryptographyContractAdvancedAES();
        contract.setSecretKey(SECRET_KEY_TEST);
        contract.setSalt(SALT_TEST);
        contract.setIv(IV_TEST);
        contract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        contract.setCryptographyIvSource(IV_FROM_PARAMETER);
        return contract;
    }

    public static CryptographyContractBasicAES argsForContractBasicAES() {
        CryptographyContractBasicAES contract = new CryptographyContractBasicAES();
        contract.setSecretKey(SECRET_KEY_TEST);
        contract.setSalt(SALT_TEST);
        contract.setIv(IV_TEST);
        contract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        contract.setCryptographyIvSource(IV_FROM_PARAMETER);
        return contract;
    }

    public static CryptographyContractRobustAES argsForContractRobustAES() {
        CryptographyContractRobustAES contract = new CryptographyContractRobustAES();
        contract.setSecretKey(SECRET_KEY_TEST);
        contract.setSalt(SALT_TEST);
        contract.setIv(IV_TEST);
        contract.setCryptographySecretKeySource(SECRET_FROM_PARAMETER);
        contract.setCryptographyIvSource(IV_FROM_PARAMETER);
        return contract;
    }

    public static CryptographyContractSimplifier3DES argsForContractSimplifier3DES(SecretKey secretKey, IvParameterSpec iv) {
        CryptographyContractSimplifier3DES contract = new CryptographyContractSimplifier3DES();
        contract.setCryptoSecretKey(secretKey);
        contract.setCryptoSpecIv(iv);
        return contract;
    }

    public static CryptographyContractSimplifierAES argsForContractSimplifierAES(SecretKey secretKey, IvParameterSpec iv) {
        CryptographyContractSimplifierAES contract = new CryptographyContractSimplifierAES();
        contract.setCryptoSecretKey(secretKey);
        contract.setCryptoSpecIv(iv);
        return contract;
    }

    public static CryptographyContractSimplifierDES argsForContractSimplifierDES(SecretKey desKey, IvParameterSpec iv) {
        CryptographyContractSimplifierDES contract = new CryptographyContractSimplifierDES();
        contract.setCryptoSecretKey(desKey);
        contract.setCryptoSpecIv(iv);
        return contract;
    }

    public static CryptographyContractSimplifierRSA argsForContractSimplifierRSA(PublicKey publicKey, PrivateKey privateKey) {
        CryptographyContractSimplifierRSA contract = new CryptographyContractSimplifierRSA();
        contract.setPublicKey(publicKey);
        contract.setPrivateKey(privateKey);
        return contract;
    }

}
