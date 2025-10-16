package com.huntercodexs.cryptography.toolkit.contract.simplifier;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptographyContractSimplifierDES {

    private SecretKey cryptoSecretKey;
    private IvParameterSpec cryptoSpecIv;

    public CryptographyContractSimplifierDES() {
    }

    public CryptographyContractSimplifierDES(SecretKey cryptoSecretKey, IvParameterSpec cryptoSpecIv) {
        this.cryptoSecretKey = cryptoSecretKey;
        this.cryptoSpecIv = cryptoSpecIv;
    }

    public SecretKey getCryptoSecretKey() {
        return cryptoSecretKey;
    }

    public void setCryptoSecretKey(SecretKey cryptoSecretKey) {
        this.cryptoSecretKey = cryptoSecretKey;
    }

    public IvParameterSpec getCryptoSpecIv() {
        return cryptoSpecIv;
    }

    public void setCryptoSpecIv(IvParameterSpec cryptoSpecIv) {
        this.cryptoSpecIv = cryptoSpecIv;
    }
}
