package com.huntercodexs.cryptography.toolkit.algorithm;

import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;

public interface CryptographyAlgorithm {

    String encrypt(CryptographyContract contract, String dataToEncrypt);
    String decrypt(CryptographyContract contract, String dataToDecrypt);

}
