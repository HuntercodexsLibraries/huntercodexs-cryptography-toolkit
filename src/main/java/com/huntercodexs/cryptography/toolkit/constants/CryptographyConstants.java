package com.huntercodexs.cryptography.toolkit.constants;

import static com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility.loadSafetyFirstValue;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility.loadSafetySecondValue;

public final class CryptographyConstants {

    public static final String SECRET_CONCAT_VALUE = "/x0t0x00001p#";
    public static final String SAFETY_FIRST_VALUE = loadSafetyFirstValue();
    public static final String SAFETY_SECOND_VALUE = loadSafetySecondValue();

    public static final int KEY_LENGTH = 256;
    public static final int ITERATION_COUNT = 65536;
    public static final String SECRET_KEY_FACTORY = "PBKDF2WithHmacSHA256";

    public static final String ENCRYPTION_DES_SCHEME = "DESede";

    public static final String AES_ALG = "AES";
    public static final String AES_CBC_PADDING = "AES/CBC/PKCS5Padding";

    public static final String AES_CBC = "AES/CBC/PKCS5Padding";
    public static final String AES = "AES";

}
