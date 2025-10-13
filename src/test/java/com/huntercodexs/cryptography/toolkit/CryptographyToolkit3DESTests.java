package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.resource.CryptographyContract;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptographyToolkit3DESTests {

    private CryptographyToolkit cryptographyToolkit;

    @Test
    public void encrypt3DesEdeTest() {
        cryptographyToolkit = new CryptographyToolkit(new CryptographyContract());
        String secretMessage = "This is a secret message, please don't break it !";
        String secretKey = "F1F2F3F4F5F6F7F8F9F00000"; /*Must have 24 bytes*/
        String encrypted = cryptographyToolkit.encrypt3desEde(secretMessage, secretKey);
        assertEquals("k4ksamLyPl+YhK0HafiFd2mbz0pt7DjvWqBX2ogtn6tPwpOfJ3m2IlmXsPSAwF+k12Poe0VUPQU=", encrypted);
    }

    @Test
    public void decrypt3DesEdeTest() {
        cryptographyToolkit = new CryptographyToolkit(new CryptographyContract());
        String encrypted = "k4ksamLyPl+YhK0HafiFd2mbz0pt7DjvWqBX2ogtn6tPwpOfJ3m2IlmXsPSAwF+k12Poe0VUPQU=";
        String secretKey = "F1F2F3F4F5F6F7F8F9F00000"; /*Must have 24 bytes*/
        String decrypted = cryptographyToolkit.decrypt3DesEde(encrypted, secretKey);
        assertEquals("This is a secret message, please don't break it !", decrypted);
    }

}
