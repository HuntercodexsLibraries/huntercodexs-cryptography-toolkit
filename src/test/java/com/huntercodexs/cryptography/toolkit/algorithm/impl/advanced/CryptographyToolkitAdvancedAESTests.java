package com.huntercodexs.cryptography.toolkit.algorithm.impl.advanced;

import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.argsForContractAdvancedAES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

@ExtendWith(MockitoExtension.class)
class CryptographyToolkitAdvancedAESTests {

    @InjectMocks
    private CryptographyAlgorithmAESImpl algorithmAES;

    @BeforeEach
    public void setUp() {
        openMocks(this);
    }

    @Test
    void shouldEncryptAES() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String secretMessage = "1234567890132456780";
        var encryptedResult = algorithmAES.encrypt(argsForContractAdvancedAES(), secretMessage);
        assertEquals("Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=", encryptedResult);
    }

    @Test
    void shouldEncryptAESWithInvalidEncryptionKeyThenThrowsCypherException() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String secretMessage = "1234567890132456780";
        var contract = argsForContractAdvancedAES();
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
        var decryptedResult = algorithmAES.decrypt(argsForContractAdvancedAES(), dataEncrypted);
        assertEquals("1234567890132456780", decryptedResult);
    }

    @Test
    void shouldDecryptAESWithInvalidEncryptionKeyThenThrowsCypherException() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String dataEncrypted = "Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=";
        var contract = argsForContractAdvancedAES();
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
        String result = algorithmAES.encrypt(argsForContractAdvancedAES(), secretMessage);
        assertEquals(88, result.length());
    }

    @Test
    public void decryptAES256CBCUsingParameterTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String dataEncrypted = "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==";
        String result = algorithmAES.decrypt(argsForContractAdvancedAES(), dataEncrypted);
        assertEquals("This is a secret message, please don't break it !", result);
    }

}
