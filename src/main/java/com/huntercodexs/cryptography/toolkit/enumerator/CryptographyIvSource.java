package com.huntercodexs.cryptography.toolkit.enumerator;

import lombok.Getter;

@Getter
public enum CryptographyIvSource {
    IV_FROM_PARAMETER,
    IV_FROM_APPLICATION_PROPERTIES,
    IV_FROM_AUTO_GENERATE;
}
