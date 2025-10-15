package com.huntercodexs.cryptography.toolkit.contract.simplifier;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@Data
@RequiredArgsConstructor
public class CryptographyContractSimplifier3DES {

    private SecretKey cryptoSecretKey;
    private IvParameterSpec cryptoSpecIv;

}
