package com.huntercodexs.cryptography.toolkit.contract.basic;

public class CryptographyContractBasicAES {

    private String secretKey;
    private String iv;

    public CryptographyContractBasicAES() {
    }

    public CryptographyContractBasicAES(String secretKey, String iv) {
        this.secretKey = secretKey;
        this.iv = iv;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}
