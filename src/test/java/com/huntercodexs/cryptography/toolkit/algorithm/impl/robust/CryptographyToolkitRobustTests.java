package com.huntercodexs.cryptography.toolkit.algorithm.impl.robust;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.contractForAesAnd3Des;
import static com.huntercodexs.cryptography.toolkit.DataBuilder.contractForAesAnd3DesFromParameters;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

class CryptographyToolkitRobustTests {

    @InjectMocks
    private CryptographyAlgorithmAESImpl algorithmAES;

    @BeforeEach
    public void setUp() {
        openMocks(this);
    }

    @Test
    public void encryptAES256CBCUsingParameterRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = algorithmAES.encrypt(contractForAesAnd3DesFromParameters(), "This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBCUsingParameterRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = algorithmAES.decrypt(
                contractForAesAnd3DesFromParameters(),
                "fatKBQJq6dGwQkgmMb+prA643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

}
