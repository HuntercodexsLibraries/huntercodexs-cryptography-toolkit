package com.huntercodexs.cryptography.toolkit.contract.basic;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class CryptographyContractBasicAES {

    private String secretKey;
    private String iv;

}
