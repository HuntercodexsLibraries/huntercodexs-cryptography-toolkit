package com.huntercodexs.cryptography.toolkit.algorithm.impl.basic;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.contractForAesAnd3Des;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

@ExtendWith(MockitoExtension.class)
class CryptographyToolkitBasicTests {

    @InjectMocks
    private CryptographyAlgorithmAESImpl algorithmAES;

    @BeforeEach
    public void setUp() {
        openMocks(this);
    }

    @Test
    public void encryptAES256CBCUsingParameterBasicTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = algorithmAES.encrypt(contractForAesAnd3Des(), "This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBCUsingParameterBasicTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = algorithmAES.decrypt(
                contractForAesAnd3Des(),
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

}
