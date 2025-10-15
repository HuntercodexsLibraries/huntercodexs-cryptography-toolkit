package com.huntercodexs.cryptography.toolkit.contract.simplifier;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@RequiredArgsConstructor
public class CryptographyContractSimplifierRSA {

    private PublicKey publicKey;
    private PrivateKey privateKey;

}
