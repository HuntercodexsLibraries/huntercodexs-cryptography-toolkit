package com.huntercodexs.cryptography.toolkit;

import com.huntercodexs.cryptography.toolkit.algorithm.impl.CryptographyAlgorithm3DESImpl;
import com.huntercodexs.cryptography.toolkit.algorithm.impl.CryptographyAlgorithmAESImpl;
import com.huntercodexs.cryptography.toolkit.algorithm.impl.CryptographyAlgorithmDESImpl;
import com.huntercodexs.cryptography.toolkit.algorithm.impl.CryptographyAlgorithmRSAImpl;
import com.huntercodexs.cryptography.toolkit.resource.CryptographyUtility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.huntercodexs.cryptography.toolkit.DataBuilder.contractForAes3Des;
import static com.huntercodexs.cryptography.toolkit.DataBuilder.rsaContract;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.MockitoAnnotations.openMocks;

@ExtendWith(MockitoExtension.class)
class CryptographyToolkitGptTests {

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
    void shouldEncryptAES() throws Exception {
        String message = "Secret Message";
        var aesKey = CryptographyUtility.generateAESKey(256);
        var aesIv = CryptographyUtility.generateIV();
        var contract =  contractForAes3Des(aesKey, aesIv);

        String aesEncrypted = algorithmAES.encrypt(contract, message);
        String aesDecrypted = algorithmAES.decrypt(contract, aesEncrypted);

        assertEquals(24, aesEncrypted.length());
        assertEquals(message, aesDecrypted);
        System.out.println("[AES] " + aesEncrypted + " -> " + aesDecrypted);
    }

    @Test
    void shouldEncryptDES() throws Exception {
        String message = "Secret Message";
        var desKey = CryptographyUtility.generateDESKey();
        var desIv = CryptographyUtility.generateIVForDES();
        var contract = contractForAes3Des(desKey, desIv);

        String desEncrypted = algorithmDES.encrypt(contract, message);
        String desDecrypted = algorithmDES.decrypt(contract, desEncrypted);

        assertEquals(24, desEncrypted.length());
        assertEquals(message, desDecrypted);
        System.out.println("[DES] " + desEncrypted + " -> " + desDecrypted);
    }

    @Test
    void shouldEncrypt3DES() throws Exception {
        String message = "Secret Message";
        var tdesKey = CryptographyUtility.generateTripleDESKey();
        var tdesIv = CryptographyUtility.generateIVForDES();
        var contract =  contractForAes3Des(tdesKey, tdesIv);

        String tdesEncrypted = algorithm3DES.encrypt(contract, message);
        String tdesDecrypted = algorithm3DES.decrypt(contract, tdesEncrypted);

        assertEquals(24, tdesEncrypted.length());
        assertEquals(message, tdesDecrypted);
        System.out.println("[3DES] " + tdesEncrypted + " -> " + tdesDecrypted);
    }

    @Test
    void shouldEncryptRSA() throws Exception {

        String message = "Secret Message";
        var rsaKeyPair = CryptographyUtility.generateRSAKeyPair(2048);
        var contract = rsaContract(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate());

        String rsaEncrypted = algorithmRSA.encrypt(contract, message);
        String rsaDecrypted = algorithmRSA.decrypt(contract, rsaEncrypted);

        assertEquals(344, rsaEncrypted.length());
        assertEquals(message, rsaDecrypted);
        System.out.println("[RSA] " + rsaEncrypted + " -> " + rsaDecrypted);
    }

}
