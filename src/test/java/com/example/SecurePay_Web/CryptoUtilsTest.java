package com.example.SecurePay_Web;

import com.example.SecurePay_Web.Utils.CryptoUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.*;
        import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoUtilsTest {

    private static KeyPair rsaKeyPair;
    private static byte[] aesKey;

    @BeforeAll
    static void setup() throws Exception {
        // Generate RSA test key pair (2048 bits)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();

        // Generate random AES-256 key
        aesKey = new byte[32];
        new SecureRandom().nextBytes(aesKey);

        System.out.println("🔑 RSA and AES keys generated for tests.");
    }

    @Test
    @DisplayName("AES-OCB encrypt/decrypt round-trip")
    void testAesOcbRoundTrip() throws Exception {
        String plaintext = "Hello AES-OCB!";
        CryptoUtils.OcbResult result = CryptoUtils.aesOcbEncryptWithRandomIV(
                aesKey, plaintext.getBytes(StandardCharsets.UTF_8)
        );

        byte[] decrypted = CryptoUtils.aesOcbDecrypt(aesKey, result.iv, result.ciphertext);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("AES-OCB IV (base64): " + Base64.getEncoder().encodeToString(result.iv));
        System.out.println("AES-OCB Ciphertext (base64): " + Base64.getEncoder().encodeToString(result.ciphertext));
        System.out.println("AES-OCB Decrypted: " + decryptedText);

        assertEquals(plaintext, decryptedText, "AES-OCB decrypted text must equal original plaintext");
    }

    @Test
    @DisplayName("RSA OAEP encrypt/decrypt round-trip")
    void testRsaOaepRoundTrip() throws Exception {
        String plaintext = "Hello RSA-OAEP!";
        byte[] encrypted = CryptoUtils.rsaEncryptWithPublic(rsaKeyPair.getPublic(),
                plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] decrypted = CryptoUtils.rsaDecryptWithPrivate(rsaKeyPair.getPrivate(), encrypted);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("RSA-OAEP Ciphertext length: " + encrypted.length);
        System.out.println("RSA-OAEP Decrypted: " + decryptedText);

        assertEquals(plaintext, decryptedText, "RSA-OAEP decrypted text must equal original plaintext");
    }

    @Test
    @DisplayName("RSA PSS sign/verify")
    void testRsaPssSignVerify() throws Exception {
        String message = "Hello RSA-PSS!";
        byte[] sig = CryptoUtils.rsaSign(rsaKeyPair.getPrivate(),
                message.getBytes(StandardCharsets.UTF_8));

        boolean isValid = CryptoUtils.rsaVerify(rsaKeyPair.getPublic(),
                message.getBytes(StandardCharsets.UTF_8), sig);

        System.out.println("RSA-PSS Signature (base64): " + Base64.getEncoder().encodeToString(sig));
        System.out.println("RSA-PSS Verification result: " + isValid);

        assertTrue(isValid, "RSA-PSS signature should verify with the correct public key");
    }

    @Test
    @DisplayName("HMAC-SHA256 compute/verify")
    void testHmacSha256() throws Exception {
        String message = "Hello HMAC!";
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        String mac = CryptoUtils.hmacSha256Base64(secret, message.getBytes(StandardCharsets.UTF_8));
        boolean isValid = CryptoUtils.hmacSha256Verify(secret, message.getBytes(StandardCharsets.UTF_8), mac);

        System.out.println("HMAC-SHA256 (base64): " + mac);
        System.out.println("HMAC-SHA256 Verification result: " + isValid);

        assertTrue(isValid, "HMAC verification should succeed for correct message");
    }

    @Test
    @DisplayName("AES-OCB tamper detection")
    void testAesOcbTamperDetection() throws Exception {
        String plaintext = "Hello tamper test!";
        CryptoUtils.OcbResult result = CryptoUtils.aesOcbEncryptWithRandomIV(
                aesKey, plaintext.getBytes(StandardCharsets.UTF_8)
        );

        // Flip one byte in ciphertext
        result.ciphertext[0] ^= 0x01;

        Exception exception = assertThrows(Exception.class, () ->
                CryptoUtils.aesOcbDecrypt(aesKey, result.iv, result.ciphertext));

        System.out.println("AES-OCB Tamper detection triggered: " + exception.getMessage());
    }
}

