package com.huntercodexs.cryptography.toolkit.resource;

import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@RequiredArgsConstructor
public class CryptographyContract {

    private String secretKey;
    private String salt;
    private String iv;

    private SecretKey cryptoSecretKey;
    private IvParameterSpec cryptoSpecIv;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private CryptographySecretKeySource cryptographySecretKeySource;
    private CryptographyIvSource cryptographyIvSource;

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
