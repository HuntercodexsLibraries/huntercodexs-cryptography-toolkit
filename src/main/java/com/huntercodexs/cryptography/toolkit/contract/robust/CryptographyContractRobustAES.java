package com.huntercodexs.cryptography.toolkit.contract.robust;

import com.huntercodexs.cryptography.toolkit.enumerator.CryptographyIvSource;
import com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource;

public class CryptographyContractRobustAES {

    public String secretKey;
    public String salt;
    public String iv;

    public CryptographySecretKeySource cryptographySecretKeySource;
    public CryptographyIvSource cryptographyIvSource;

    public CryptographyContractRobustAES() {
    }

    public CryptographyContractRobustAES(String secretKey, String salt, String iv, CryptographySecretKeySource cryptographySecretKeySource, CryptographyIvSource cryptographyIvSource) {
        this.secretKey = secretKey;
        this.salt = salt;
        this.iv = iv;
        this.cryptographySecretKeySource = cryptographySecretKeySource;
        this.cryptographyIvSource = cryptographyIvSource;
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

    public CryptographySecretKeySource getCryptographySecretKeySource() {
        return cryptographySecretKeySource;
    }

    public void setCryptographySecretKeySource(CryptographySecretKeySource cryptographySecretKeySource) {
        this.cryptographySecretKeySource = cryptographySecretKeySource;
    }

    public CryptographyIvSource getCryptographyIvSource() {
        return cryptographyIvSource;
    }

    public void setCryptographyIvSource(CryptographyIvSource cryptographyIvSource) {
        this.cryptographyIvSource = cryptographyIvSource;
    }
}
