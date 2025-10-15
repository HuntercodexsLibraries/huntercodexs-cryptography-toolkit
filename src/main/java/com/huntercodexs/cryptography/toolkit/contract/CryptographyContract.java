package com.huntercodexs.cryptography.toolkit.contract;

import com.huntercodexs.cryptography.toolkit.enumerator.CryptographyIvSource;
import com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Data
@Getter
@RequiredArgsConstructor
public class CryptographyContract {

    private String secretKey;
    private String salt;
    private String iv;

    private CryptographySecretKeySource cryptographySecretKeySource;
    private CryptographyIvSource cryptographyIvSource;

}
