package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.argsForContractAdvanced3DES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

@ExtendWith(MockitoExtension.class)
class CryptographyToolkitAdvanced3DESTests {

    @InjectMocks
    private CryptographyAlgorithm3DESImpl algorithm3DES;

    @BeforeEach
    public void setUp() {
        openMocks(this);
    }

    @Test
    public void encrypt3DesEdeTest() {
        String secretMessage = "This is a secret message, please don't break it !";
        String encrypted = algorithm3DES.encrypt(argsForContractAdvanced3DES(), secretMessage);
        assertEquals("mI2NNMBh0yyItBbeGfEUFB/bkS8DGm7gR5il+Uz9Oj6K9gLIF0rdPt+jV0U+Up75GsZsMGr8nmE=", encrypted);
    }

    @Test
    public void decrypt3DesEdeTest() {
        String encrypted = "mI2NNMBh0yyItBbeGfEUFB/bkS8DGm7gR5il+Uz9Oj6K9gLIF0rdPt+jV0U+Up75GsZsMGr8nmE=";
        String decrypted = algorithm3DES.decrypt(argsForContractAdvanced3DES(), encrypted);
        assertEquals("This is a secret message, please don't break it !", decrypted);
    }

}
