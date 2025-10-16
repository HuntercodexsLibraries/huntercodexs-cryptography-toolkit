package com.huntercodexs.cryptography.toolkit.contract.advanced;

public class CryptographyContractAdvancedAES {

    private String secretKey;
    private String salt;
    private String iv;

    public CryptographyContractAdvancedAES() {
    }

    public CryptographyContractAdvancedAES(String secretKey, String salt, String iv) {
        this.secretKey = secretKey;
        this.salt = salt;
        this.iv = iv;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}
