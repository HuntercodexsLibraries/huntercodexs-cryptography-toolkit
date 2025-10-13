package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.exception.CryptographyException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.huntercodexs.cryptography.toolkit.CryptographyToolkit.decryptAES;
import static com.huntercodexs.cryptography.toolkit.CryptographyToolkit.encryptAES;
import static com.huntercodexs.cryptography.toolkit.DataBuilder.SECRET_KEY_TEST;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptographyToolkitOldVersionTests {

    @Test
    void shouldEncryptAES() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        var encryptedResult = encryptAES("1234567890132456780", SECRET_KEY_TEST);
        assertEquals("Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=", encryptedResult);
    }

    @Test
    void shouldEncryptAESWithInvalidEncryptionKeyThenThrowsCypherException() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        var exception = Assertions.assertThrows(CryptographyException.class, () -> {
            encryptAES("1234567890132456780", "invalid");
        });

        assertEquals("Invalid AES key length: 7 bytes", exception.getMessage());
    }

    @Test
    void shouldDecryptAES() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        var decryptedResult = decryptAES("Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=", SECRET_KEY_TEST);
        assertEquals("1234567890132456780", decryptedResult);
    }

    @Test
    void shouldDecryptAESWithInvalidEncryptionKeyThenThrowsCypherException() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        var exception = Assertions.assertThrows(CryptographyException.class, () -> {
            decryptAES("Pi2hAKbr/0tR1fUDVI3R5RlzHou09sGcaMu+ZLOUNpo=", "invalid");
        });

        assertEquals("Invalid AES key length: 7 bytes", exception.getMessage());
    }

    @Test
    public void encryptAES256CBC_PARAMETER_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAES("This is a secret message, please don't break it !", SECRET_KEY_TEST);
        assertEquals(88, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMTER_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAES(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", SECRET_KEY_TEST);
        assertEquals("This is a secret message, please don't break it !", result);
    }

}
