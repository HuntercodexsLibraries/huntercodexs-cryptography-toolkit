package com.huntercodexs.cryptography.toolkit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.huntercodexs.cryptography.toolkit.CryptographyToolkit.decryptAes256CbcAutomatic;
import static com.huntercodexs.cryptography.toolkit.CryptographyToolkit.encryptAes256CbcAutomatic;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographyToolkitTests {

    DataBuilder dataBuilder;
    CryptographyToolkit cryptographyToolkit;

    @BeforeEach
    public void setUp() {
        dataBuilder = new DataBuilder();
    }

    @Test
    public void encryptAES256CBCUsingParameterStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromParameters(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBCUsingParameterStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromParameters(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingParameterAndApplicationPropertiesStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndApplicationProperties(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBCUsingParameterAndApplicationPropertiesStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndApplicationProperties(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingParameterAndAutoGenerateStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "This is a secret message, please don't break it !");
        assertEquals(148, result.length());
    }

    @Test
    public void decryptAES256CBCUsingParameterAndAutoGenerateStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "B92740F33TqkR/aGtPP4/7+pZDlX3vU/XmEbw3hQ1Uuv0FH6ZmIO0HXKEALs8OjB4MDAxMDE6/x0t0x00001p#FAEE4BCCnR47qBSgJBo961ibQ2S/aKXE3HY5MThrjm7e2uzZ/4Dhd7+m9PQ5Xi");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndParameterStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationPropertiesAndParameter(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndParameterStaticRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationPropertiesAndParameter(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationProperties(),"This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesRobustTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationProperties(),
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndAutoGenerateTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),"This is a secret message, please don't break it !");
        assertEquals(148, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndAutoGenerateTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),
                "2362723DR0qVkaPiE7buDfxjB7f3i528IfQ8d6HbvPwB+Mw8hOj4D+PFtHRisOjB4MDAxMDE6/x0t0x00001p#45B046EFMcBRd9nDXagyVumfvARzDZOe1i3HhEQZc9YccQHLV2KGeYgoUAjcZP");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndAutoGenerate2_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),"secret message");
        assertEquals(84, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndAutoGenerate2_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "1007ACF1HyiP+w82rO31HQwRc2NNgOjB4MDAxMDE6/x0t0x00001p#77304610R49EsAxbjohtjsfASJ2r/Q");
        assertEquals("secret message", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndAutoGenerate3_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "64.877.334/0001-58");
        assertEquals(93, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndAutoGenerate3_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAes256CbcRobust(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "F62C2C2FT16yOR5rFEESyVomYUPtXimombw7Xekn/x0t0x00001p#6D8841E8N7cqx6diEmQZaAdBFwf62wkL6M33dZwJ");
        assertEquals("64.877.334/0001-58", result);
    }

    @Test
    public void automaticEncryptTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = encryptAes256CbcAutomatic("This is a secret message, please don't break it !");
        assertEquals(171, result.length());
        assertTrue(result.contains("/x0t0x00001p#"));

        String resultDecrypt = decryptAes256CbcAutomatic(result);
        assertEquals("This is a secret message, please don't break it !", resultDecrypt);
    }

    @Test
    public void automaticDecryptTest() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = decryptAes256CbcAutomatic(
                "NDFFNjQ2RUQ$MEU0QjRFNTQ$XD+LSM87ZC5aR2wly25mVYzlsLnOe90aH375GjUTmgOjB4MDAxMDE6OjB4MTEwMTA6/x0t0x00001p#REY0QjQ0NTM$MzA1RTIxNTE$6Nhqt/JrdfgMDO3l1d4pLMs6iO3qk6Xe5tQS5yY+/5cH");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_PARAMTER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndApplicationProperties());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_PARAMTER_AND_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndApplicationProperties());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("This is a secret message, please don't break it !");
        assertEquals(104, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic(
                "07E1C9C864B74206p7Yc0lGZsgCPG8BclOfj7ONkFhh+GlzK6jYW569dLcdeAyqvuXYBTelFvhH3OUP1kd0SzAOODw+vT+71FxRw6Q==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndParameter());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndParameter());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationProperties());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationProperties());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndAutoGenerate1Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("This is a secret message, please don't break it !");
        assertEquals(104, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndAutoGenerate1Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic(
                "E8D90D9F85DA497EeS8aT4GNehZGLrxIxL+CJAvsk2FlUmOBg2i6V6VSeuGzS9A4UF7vxhvvAWpnhJ9kcXtx8ktPiobwZOhvuVfeyw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndAutoGenerate2Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("secret message");
        assertEquals(40, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndAutoGenerate2Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic("23F78070600E4B2EX4yQiC8AZNyUZ9iYIbK0fw==");
        assertEquals("secret message", result);
    }

    @Test
    public void encryptAES256CBCUsingApplicationPropertiesAndAutoGenerate3Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.encryptAes256CbcDynamicBasic("64.877.334/0001-58");
        assertEquals(60, result.length());
    }

    @Test
    public void decryptAES256CBCUsingApplicationPropertiesAndAutoGenerate3Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAes256CbcDynamicBasic("0A31DEC9DA3C4B4EA4LUc8BgdBg4w74A1tOhbKGB8ZThBX6I49ogH3Uo13k=");
        assertEquals("64.877.334/0001-58", result);
    }

}
