package com.huntercodexs.cryptography.toolkit.algorithm;

public interface CryptographyAlgorithm<T> {

    T encrypt(T contract, String dataToEncrypt);
    T decrypt(T contract, String dataToDecrypt);

}
