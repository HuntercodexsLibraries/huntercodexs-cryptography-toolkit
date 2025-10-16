package com.huntercodexs.cryptography.toolkit.contract.simplifier;

import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptographyContractSimplifierRSA {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public CryptographyContractSimplifierRSA() {
    }

    public CryptographyContractSimplifierRSA(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
