package com.huntercodexs.cryptography.toolkit.algorithm;

public interface CryptographyAlgorithm<T> {

    String encrypt(T contract, String dataToEncrypt);
    String decrypt(T contract, String dataToDecrypt);

}
