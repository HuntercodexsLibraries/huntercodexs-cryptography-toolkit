package com.huntercodexs.cryptography.toolkit.algorithm.impl.basic;

import com.huntercodexs.cryptography.toolkit.algorithm.CryptographyAlgorithm;
import com.huntercodexs.cryptography.toolkit.contract.basic.CryptographyContractBasicAES;
import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import lombok.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_ALGORITHM_TYPE_FOR_SPEC;
import static com.huntercodexs.cryptography.toolkit.constants.CryptographyConstants.AES_INSTANCE_TYPE_FOR_CIPHER;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * AES (Symmetric)
 * */
public class CryptographyAlgorithmAESImpl implements CryptographyAlgorithm<Object> {

    @Generated
    public static final Logger log = LoggerFactory.getLogger(CryptographyAlgorithmAESImpl.class);

    @Override
    public String encrypt(Object contract, String dataToEncrypt) {
        return encryptAes256CbcBasic(dataToEncrypt, (CryptographyContractBasicAES) contract);
    }

    @Override
    public String decrypt(Object contract, String dataToDecrypt) {
        return decryptAes256CbcBasic(dataToDecrypt, (CryptographyContractBasicAES) contract);
    }

    private String encryptAes256CbcBasic(String dataToEncrypt, CryptographyContractBasicAES contract) {
        try {

            Key keySpec = new SecretKeySpec(contract.getSecretKey().getBytes(), AES_ALGORITHM_TYPE_FOR_SPEC);
            AlgorithmParameterSpec param = new IvParameterSpec(contract.getIv().getBytes());
            Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
            byte[] bytes = cipher.doFinal(dataToEncrypt.getBytes(UTF_8));
            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            log.error("Fail in CryptographyAlgorithmAESImpl.encryptAes256CbcBasic: {}", e.getMessage());
            throw new CryptographyException(e.getMessage());
        }
    }

    private String decryptAes256CbcBasic(String dataToDecrypt, CryptographyContractBasicAES contract) {
        try {

            Key keySpec = new SecretKeySpec(contract.getSecretKey().getBytes(), AES_ALGORITHM_TYPE_FOR_SPEC);
            AlgorithmParameterSpec param = new IvParameterSpec(contract.getIv().getBytes());
            Cipher cipher = Cipher.getInstance(AES_INSTANCE_TYPE_FOR_CIPHER);
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
