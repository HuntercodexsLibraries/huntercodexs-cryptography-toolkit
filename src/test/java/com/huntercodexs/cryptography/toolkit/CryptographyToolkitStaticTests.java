package com.huntercodexs.cryptography.toolkit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptographyToolkitStaticTests {

    private DataBuilder dataBuilder;

    @BeforeEach
    public void setUp() {
        dataBuilder = new DataBuilder();
    }

    @Test
    public void encryptAES256CBC_PARAMETER_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParameters(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMTER_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParameters(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_APPLICATION_PROPERTIES_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndApplicationProperties(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMTER_AND_APPLICATION_PROPERTIES_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndApplicationProperties(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "This is a secret message, please don't break it !");
        assertEquals(148, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "B92740F33TqkR/aGtPP4/7+pZDlX3vU/XmEbw3hQ1Uuv0FH6ZmIO0HXKEALs8OjB4MDAxMDE6/x0t0x00001p#FAEE4BCCnR47qBSgJBo961ibQ2S/aKXE3HY5MThrjm7e2uzZ/4Dhd7+m9PQ5Xi");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndParameter(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndParameter(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationProperties(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationProperties(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),"This is a secret message, please don't break it !");
        assertEquals(148, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),
                "2362723DR0qVkaPiE7buDfxjB7f3i528IfQ8d6HbvPwB+Mw8hOj4D+PFtHRisOjB4MDAxMDE6/x0t0x00001p#45B046EFMcBRd9nDXagyVumfvARzDZOe1i3HhEQZc9YccQHLV2KGeYgoUAjcZP");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),"secret message");
        assertEquals(84, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "1007ACF1HyiP+w82rO31HQwRc2NNgOjB4MDAxMDE6/x0t0x00001p#77304610R49EsAxbjohtjsfASJ2r/Q");
        assertEquals("secret message", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_3_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "64.877.334/0001-58");
        assertEquals(93, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_3_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "F62C2C2FT16yOR5rFEESyVomYUPtXimombw7Xekn/x0t0x00001p#6D8841E8N7cqx6diEmQZaAdBFwf62wkL6M33dZwJ");
        assertEquals("64.877.334/0001-58", result);
    }

}
