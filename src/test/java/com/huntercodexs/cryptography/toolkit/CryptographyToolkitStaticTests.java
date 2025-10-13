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
        assertEquals(140, result.length());
    }

    @Test
    public void decryptAES256CBC_PARAMETER_AND_AUTO_GENERATE_IV_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),

                "9DC314F85d0I8HrM/5+kYUOafFoDNxQGtdIdQnSZlLbERWWL0IK5srk2dYCzU:EQ:/x0t0x00001p#04504511Hmg0/oKQJL8aUjWAQl89uRdYGP3WghfSIfvlEB4SvhP6K4WAIjk0wd");
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
        assertEquals(140, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),
                "292C415BeBB1Tx053xLmqPCPCmQ8hyPmUu7aScuWb0W0fstwna6o2tOB9CjTo:EQ:/x0t0x00001p#CFBA406E47Z29st+nvb4Cek9smqzyzhp+E5cAkBb02nFSxto63fppdCsEh6i2j");
        assertEquals("This is a secret message, please don't break it !", result);
    }

    @Test
    public void encryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.encryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromApplicationPropertiesAndAutoGenerate(),"secret message");
        assertEquals(76, result.length());
    }

    @Test
    public void decryptAES256CBC_APPLICATION_PROPERTIES_AUTO_GENERATE_IV_2_Static_Test() {
        /* ! DO NOT CHANGE THE INFORMATION HERE ! */
        String result = CryptographyToolkit.decryptAesCbc256StaticSTRONGER(
                dataBuilder.resourceFromParametersAndAutoGenerate(),
                "94EF2A5FiYcZ31u4rsn/iFDfaD/pM:EQ:/x0t0x00001p#67984EE4q9sEHnHU2/aHLfLtUuMWW7");
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
