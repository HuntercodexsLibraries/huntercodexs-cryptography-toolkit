package com.huntercodexs.cryptography.toolkit.constants;

import static com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility.loadSafetyFirstValue;
import static com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility.loadSafetySecondValue;

public final class CryptographyConstants {

    public static final String SECRET_CONCAT_VALUE = "/x0t0x00001p#";
    public static final String SAFETY_FIRST_VALUE = loadSafetyFirstValue();
    public static final String SAFETY_SECOND_VALUE = loadSafetySecondValue();

    public static final String TRIPLE_DES_SECRET_KEY_INSTANCE_FACTORY = "DESede";

    public static final int AES_KEY_LENGTH_FOR_SPEC = 256;
    public static final int AES_ITERATION_COUNT_FOR_SPEC = 65536;
    public static final String AES_ALGORITHM_TYPE_FOR_SPEC = "AES";
    public static final String AES_INSTANCE_TYPE_FOR_CIPHER = "AES/CBC/PKCS5Padding";
    public static final String AES_SECRET_KEY_INSTANCE_FACTORY = "PBKDF2WithHmacSHA256";

}
