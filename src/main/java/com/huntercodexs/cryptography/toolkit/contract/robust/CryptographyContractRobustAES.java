package com.huntercodexs.cryptography.toolkit.contract.robust;

import com.huntercodexs.cryptography.toolkit.enumerator.CryptographyIvSource;
import com.huntercodexs.cryptography.toolkit.enumerator.CryptographySecretKeySource;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class CryptographyContractRobustAES {

    public String secretKey;
    public String salt;
    public String iv;

    public CryptographySecretKeySource cryptographySecretKeySource;
    public CryptographyIvSource cryptographyIvSource;

}
