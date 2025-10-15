package com.huntercodexs.cryptography.toolkit.contract.robust;

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
public class CryptographyContractRobustAES {

    public String secretKey;
    public String salt;
    public String iv;

    public SecretKey cryptoSecretKey;
    public IvParameterSpec cryptoSpecIv;

    public PublicKey publicKey;
    public PrivateKey privateKey;

    public CryptographySecretKeySource cryptographySecretKeySource;
    public CryptographyIvSource cryptographyIvSource;

}
