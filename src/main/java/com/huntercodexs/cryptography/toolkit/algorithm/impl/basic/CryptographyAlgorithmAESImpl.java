package com.huntercodexs.cryptography.toolkit.algorithm.impl.basic;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import com.huntercodexs.cryptography.toolkit.process.CryptographyToolkitProcessor;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES;
import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_CBC;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm {

    @Generated
    public static final Logger log = LoggerFactory.getLogger(CryptographyAlgorithmAESImpl.class);

    CryptographyToolkitProcessor processor;

    @Override
    public String encrypt(CryptographyContract contract, String dataToEncrypt) {
        this.processor = new CryptographyToolkitProcessor(contract);
        return encryptAes256CbcBasic(dataToEncrypt, contract);
    }

    @Override
    public String decrypt(CryptographyContract contract, String dataToDecrypt) {
        this.processor = new CryptographyToolkitProcessor(contract);
        return decryptAes256CbcBasic(dataToDecrypt, contract);
    }

    private String encryptAes256CbcBasic(String dataToEncrypt, CryptographyContract contract) {
        try {

            Key keySpec = new SecretKeySpec(contract.getSecretKey().getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(contract.getIv().getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] bytes = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));
            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.encryptAes256CbcBasic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String decryptAes256CbcBasic(String dataToDecrypt, CryptographyContract contract) {
        try {

            Key keySpec = new SecretKeySpec(contract.getSecretKey().getBytes(), AES);
            AlgorithmParameterSpec param = new IvParameterSpec(contract.getIv().getBytes());
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
            byte[] bytes = Base64.getDecoder().decode(dataToDecrypt.getBytes(UTF_8));
            byte[] decValue = cipher.doFinal(bytes);
            return new String(decValue);

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.decryptAes256CbcBasic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }
}
