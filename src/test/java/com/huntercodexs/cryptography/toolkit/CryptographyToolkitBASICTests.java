package com.huntercodexs.cryptography.toolkit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptographyToolkitBASICTests {

    private DataBuilder dataBuilder;
    private CryptographyToolkit cryptographyToolkit;

    @BeforeEach
    public void setUp() {
        dataBuilder = new DataBuilder();
    }

    @Test
    public void encryptAES256CBC_PARAMETER_BASIC_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.encryptAesCbc256BASIC("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_PARAMTER_BASIC_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.decryptAesCbc256BASIC(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

}
