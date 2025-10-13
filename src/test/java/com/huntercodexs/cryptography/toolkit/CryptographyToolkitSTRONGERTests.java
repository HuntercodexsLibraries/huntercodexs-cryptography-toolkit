package com.huntercodexs.cryptography.toolkit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptographyToolkitSTRONGERTests {

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
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMTER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParameters());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndApplicationProperties());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMTER_AND_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndApplicationProperties());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("This is a secret message, please don't break it !");
        assertEquals(148, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "25544C61m0nYPvFyBEU2K9idF5gSnTdMZQxZY4ryUW0vm2NcMMUlpg87e9rxYOjB4MDAxMDE6/x0t0x00001p#84EB4B4ET51PCA3maiFPmv+HfHX5aIjHuWok3kZ5LYvLXFyF139k1DTOYoAzYz");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndParameter());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AND_PARAMETER_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndParameter());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationProperties());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("This is a secret message, please don't break it !");
        assertEquals(108, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationProperties());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "zQj5INzIi2XrRsd+sgevBw643nGrl7NdCREheb+dcCx++BOk+NgHQ9QBVAbv9VvEkJGyoLvzpgUGBm9R6h2ujVEvFgJakxOedNuZfPZ3XOE=");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("This is a secret message, please don't break it !");
        assertEquals(148, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "B5EFC6FFnGrQmGyMwXZGdsUqZ61F0ycvAjOeL05/21EKSqDQq++MNLeIn9lqkOjB4MDAxMDE6/x0t0x00001p#D8374853KYTQHqlAIh3BkBgX33h1u4rXa8Ll4Jc9xpktrrU1+EqpRCQuP5dICn");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("secret message");
        assertEquals(84, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER("F52803F4EJZG43m9SQnlGMsmuthbsOjB4MDAxMDE6/x0t0x00001p#12AE473B6lvRToWC03LWsD86vlq8Lc");
        assertEquals("secret message", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_3_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("64.877.334/0001-58");
        assertEquals(93, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_3_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER("F62C2C2FT16yOR5rFEESyVomYUPtXimombw7Xekn/x0t0x00001p#6D8841E8N7cqx6diEmQZaAdBFwf62wkL6M33dZwJ");
        assertEquals("64.877.334/0001-58", result);
    }

}
