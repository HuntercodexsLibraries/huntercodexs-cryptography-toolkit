package com.huntercodexs.cryptography.toolkit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographyToolkitDynamicBASICTests {

    private DataBuilder dataBuilder;
    private CryptographyToolkit cryptographyToolkit;

    @BeforeEach
    public void setUp() {
        dataBuilder = new DataBuilder();
    }

    @Test
    public void encryptAES256CBC_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_PARAMTER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndApplicationProperties());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_PARAMTER_AND_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndApplicationProperties());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("This is a secret message, please don't break it !");
        assertEquals(104, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC(
                "07E1C9C864B74206p7Yc0lGZsgCPG8BclOfj7ONkFhh+GlzK6jYW569dLcdeAyqvuXYBTelFvhH3OUP1kd0SzAOODw+vT+71FxRw6Q==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndParameter());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndParameter());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationProperties());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("This is a secret message, please don't break it !");
        assertEquals(88, result.length());
        assertEquals("X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==", result);
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationProperties());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC(
                "X52zJxNJS3fw36WjXLZ3zTdoepOy1ufFOScHVCTFwcr9uTdIHwXlzsWtGUv73HNKkLeMy5CYDk8tVhYpvz31lw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("This is a secret message, please don't break it !");
        assertEquals(104, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC(
                "E8D90D9F85DA497EeS8aT4GNehZGLrxIxL+CJAvsk2FlUmOBg2i6V6VSeuGzS9A4UF7vxhvvAWpnhJ9kcXtx8ktPiobwZOhvuVfeyw==");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("secret message");
        assertEquals(40, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC("23F78070600E4B2EX4yQiC8AZNyUZ9iYIbK0fw==");
        assertEquals("secret message", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_3_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256DynamicBASIC("64.877.334/0001-58");
        assertEquals(60, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_3_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256DynamicBASIC("0A31DEC9DA3C4B4EA4LUc8BgdBg4w74A1tOhbKGB8ZThBX6I49ogH3Uo13k=");
        assertEquals("64.877.334/0001-58", result);
    }

}
