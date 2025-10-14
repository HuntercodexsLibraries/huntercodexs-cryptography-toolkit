package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.contractForAesAnd3Des;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

@ExtendWith(MockitoExtension.class)
class CryptographyToolkitAdvancedTests {

    @InjectMocks
    private CryptographyAlgorithm3DESImpl algorithm3DES;

    @InjectMocks
    private CryptographyAlgorithmAESImpl algorithmAES;

    @BeforeEach
    public void setUp() {
        openMocks(this);
    }

    @Test
    public void encrypt3DesEdeTest() {
        String secretMessage = "This is a secret message, please don't break it !";
        String encrypted = algorithm3DES.encrypt(contractForAesAnd3Des(), secretMessage);
        assertEquals("mI2NNMBh0yyItBbeGfEUFB/bkS8DGm7gR5il+Uz9Oj6K9gLIF0rdPt+jV0U+Up75GsZsMGr8nmE=", encrypted);
    }

    @Test
    public void decrypt3DesEdeTest() {
        String encrypted = "mI2NNMBh0yyItBbeGfEUFB/bkS8DGm7gR5il+Uz9Oj6K9gLIF0rdPt+jV0U+Up75GsZsMGr8nmE=";
        String decrypted = algorithm3DES.decrypt(contractForAesAnd3Des(), encrypted);
        assertEquals("This is a secret message, please don't break it !", decrypted);
    }

    @Test
    void shouldEncryptAES() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String secretMessage = "1234567890132456780";
        var encryptedResult = algorithmAES.encrypt(contractForAesAnd3Des(), secretMessage);
        assertEquals("Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=", encryptedResult);
    }

    @Test
    void shouldEncryptAESWithInvalidEncryptionKeyThenThrowsCypherException() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String secretMessage = "1234567890132456780";
        var contract = contractForAesAnd3Des();
        contract.setSecretKey("invalid");

        var exception = Assertions.assertThrows(CryptographyException.class, () -> {
            algorithmAES.encrypt(contract, "invalid");
        });

        assertEquals("Invalid AES key length: 7 bytes", exception.getMessage());
    }

    @Test
    void shouldDecryptAES() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String dataEncrypted = "Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=";
        var decryptedResult = algorithmAES.decrypt(contractForAesAnd3Des(), dataEncrypted);
        assertEquals("1234567890132456780", decryptedResult);
    }

    @Test
    void shouldDecryptAESWithInvalidEncryptionKeyThenThrowsCypherException() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String dataEncrypted = "Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=";
        var contract = contractForAesAnd3Des();
        contract.setSecretKey("invalid");

        var exception = Assertions.assertThrows(CryptographyException.class, () -> {
            algorithmAES.encrypt(contract, dataEncrypted);
        });

        assertEquals("Invalid AES key length: 7 bytes", exception.getMessage());
    }

    @Test
    public void encryptAES256CBCUsingParameterTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String secretMessage = "This is a secret message, please don't break it !";
        String result = algorithmAES.encrypt(contractForAesAnd3Des(), secretMessage);
        assertEquals(88, result.length());
    }

    @Test
    public void decryptAES256CBCUsingParameterTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String dataEncrypted = "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==";
        String result = algorithmAES.decrypt(contractForAesAnd3Des(), dataEncrypted);
        assertEquals("This is a secret message, please don't break it !", result);
    }

}
