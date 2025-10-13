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
        assertEquals(140, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "9DC314F85d0I8HrM/5+kYUOafFoDNxQGtdIdQnSZlLbERWWL0IK5srk2dYCzU:EQ:/x0t0x00001p#04504511Hmg0/oKQJL8aUjWAQl89uRdYGP3WghfSIfvlEB4SvhP6K4WAIjk0wd");
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
        assertEquals(140, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER(
                "292C415BeBB1Tx053xLmqPCPCmQ8hyPmUu7aScuWb0W0fstwna6o2tOB9CjTo:EQ:/x0t0x00001p#CFBA406E47Z29st+nvb4Cek9smqzyzhp+E5cAkBb02nFSxto63fppdCsEh6i2j");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate());
        String result = cryptographyToolkit.encryptAesCbc256STRONGER("secret message");
        assertEquals(76, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        cryptographyToolkit = new CryptographyToolkit(dataBuilder.resourceFromParametersAndAutoGenerate());
        String result = cryptographyToolkit.decryptAesCbc256STRONGER("94EF2A5FiYcZ31u4rsn/iFDfaD/pM:EQ:/x0t0x00001p#67984EE4q9sEHnHU2/aHLfLtUuMWW7");
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
