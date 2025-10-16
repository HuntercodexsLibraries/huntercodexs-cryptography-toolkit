package com.huntercodexs.cryptography.toolkit.contract.advanced;

public class CryptographyContractAdvanced3DES {

    private String secretKey;

    public CryptographyContractAdvanced3DES() {
    }

    public CryptographyContractAdvanced3DES(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
}
