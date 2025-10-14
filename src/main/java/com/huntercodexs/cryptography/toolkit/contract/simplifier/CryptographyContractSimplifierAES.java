package com.huntercodexs.cryptography.toolkit.contract.simplifier;

import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@RequiredArgsConstructor
public class CryptographyContractSimplifierAES {

    public String secretKey;
    public String salt;
    public String iv;

    public SecretKey cryptoSecretKey;
    public IvParameterSpec cryptoSpecIv;

    public PublicKey publicKey;
    public PrivateKey privateKey;

    public CryptographySecretKeySource cryptographySecretKeySource;
    public CryptographyIvSource cryptographyIvSource;

    @Getter
    public enum CryptographySecretKeySource {
        SECRET_FROM_PARAMETER,
        SECRET_FROM_APPLICATION_PROPERTIES;
    }

    @Getter
    public enum CryptographyIvSource {
        IV_FROM_PARAMETER,
        IV_FROM_APPLICATION_PROPERTIES,
        IV_FROM_AUTO_GENERATE;
    }
}
