package com.huntercodexs.cryptography.toolkit.contract.advanced;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class CryptographyContractAdvancedAES {

    private String secretKey;
    private String salt;
    private String iv;

}
