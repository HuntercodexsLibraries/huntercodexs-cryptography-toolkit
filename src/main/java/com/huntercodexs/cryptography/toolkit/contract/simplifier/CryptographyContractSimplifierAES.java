package com.huntercodexs.cryptography.toolkit.contract.simplifier;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@Data
@RequiredArgsConstructor
public class CryptographyContractSimplifierAES {

    public SecretKey cryptoSecretKey;
    public IvParameterSpec cryptoSpecIv;

}
