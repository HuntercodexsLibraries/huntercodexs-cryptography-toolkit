package com.huntercodexs.cryptography.toolkit.contract.advanced;

import com.huntercodexs.cryptography.toolkit.enumerator.CryptographyIvSource;
import com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@RequiredArgsConstructor
public class CryptographyContractAdvancedAES {

    private String secretKey;
    private String salt;
    private String iv;

    private SecretKey cryptoSecretKey;
    private IvParameterSpec cryptoSpecIv;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private CryptographySecretKeySource cryptographySecretKeySource;
    private CryptographyIvSource cryptographyIvSource;

}
