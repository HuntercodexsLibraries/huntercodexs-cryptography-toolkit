package com.huntercodexs.cryptography.toolkit.algorithm.impl.simplifier;

import com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

@ExtendWith(MockitoExtension.class)
class CryptographyToolkitSimpleTests {

    @InjectMocks
    private CryptographyAlgorithmDESImpl algorithmDES;

    @InjectMocks
    private CryptographyAlgorithm3DESImpl algorithm3DES;

    @InjectMocks
    private CryptographyAlgorithmAESImpl algorithmAES;

    @InjectMocks
    private CryptographyAlgorithmRSAImpl algorithmRSA;

    @BeforeEach
    public void setUp() {
        openMocks(this);
    }

    @Test
    void shouldEncryptDESSimpleTest() throws Exception {
        String message = "Secret Message";
        var desKey = CryptographyUtility.generateDESKeyUtility();
        var desIv = CryptographyUtility.generateIvForDESUtility();
        var contract = argsForContractSimplifierDES(desKey, desIv);

        String desEncrypted = algorithmDES.encrypt(contract, message);
        String desDecrypted = algorithmDES.decrypt(contract, desEncrypted);

        assertEquals(24, desEncrypted.length());
        assertEquals(message, desDecrypted);
        System.out.println("[DES] " + desEncrypted + " -> " + desDecrypted);
    }

    @Test
    void shouldEncrypt3DESSimpleTest() throws Exception {
        String message = "Secret Message";
        var tdesKey = CryptographyUtility.generateTripleDESKeyUtility();
        var tdesIv = CryptographyUtility.generateIvForDESUtility();
        var contract =  argsForContractSimplifier3DES(tdesKey, tdesIv);

        String tdesEncrypted = algorithm3DES.encrypt(contract, message);
        String tdesDecrypted = algorithm3DES.decrypt(contract, tdesEncrypted);

        assertEquals(24, tdesEncrypted.length());
        assertEquals(message, tdesDecrypted);
        System.out.println("[3DES] " + tdesEncrypted + " -> " + tdesDecrypted);
    }

    @Test
    void shouldEncryptAESSimpleTest() throws Exception {
        String message = "Secret Message";
        var aesKey = CryptographyUtility.generateAESKeyUtility(256);
        var aesIv = CryptographyUtility.generateIvUtility();
        var contract =  argsForContractSimplifierAES(aesKey, aesIv);

        String aesEncrypted = algorithmAES.encrypt(contract, message);
        String aesDecrypted = algorithmAES.decrypt(contract, aesEncrypted);

        assertEquals(24, aesEncrypted.length());
        assertEquals(message, aesDecrypted);
        System.out.println("[AES] " + aesEncrypted + " -> " + aesDecrypted);
    }

    @Test
    void shouldEncryptRSASimpleTest() throws Exception {

        String message = "Secret Message";
        var rsaKeyPair = CryptographyUtility.generateRSAKeyPairUtility(2048);
        var contract = argsForContractSimplifierRSA(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate());

        String rsaEncrypted = algorithmRSA.encrypt(contract, message);
        String rsaDecrypted = algorithmRSA.decrypt(contract, rsaEncrypted);

        assertEquals(344, rsaEncrypted.length());
        assertEquals(message, rsaDecrypted);
        System.out.println("[RSA] " + rsaEncrypted + " -> " + rsaDecrypted);
    }

}
