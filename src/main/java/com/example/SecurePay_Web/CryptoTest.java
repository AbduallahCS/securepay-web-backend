package com.example.SecurePay_Web;

import java.util.Arrays;

public class CryptoTest {

    public static void main(String[] args) throws Exception {
        testStringByteConversion();
        testBase64EncodeDecode();
        testAesOcbEncryptDecrypt();
        System.out.println("All tests completed successfully!");
    }

    private static void testStringByteConversion() {
        String original = "Hello, SecurePay!";
        byte[] bytes = CryptoUtils.stringToBytes(original);
        String restored = CryptoUtils.bytesToString(bytes);

        if (!original.equals(restored)) {
            throw new RuntimeException("String <-> byte[] conversion failed");
        } else {
            System.out.println("String <-> byte[] test passed");
        }
    }

    private static void testBase64EncodeDecode() {
        String original = "SecurePay123";
        byte[] bytes = CryptoUtils.stringToBytes(original);
        String encoded = CryptoUtils.base64Encode(bytes);
        byte[] decoded = CryptoUtils.base64Decode(encoded);
        String restored = CryptoUtils.bytesToString(decoded);

        if (!original.equals(restored)) {
            throw new RuntimeException("Base64 encode/decode failed");
        } else {
            System.out.println("Base64 encode/decode test passed");
        }
    }

    private static void testAesOcbEncryptDecrypt() throws Exception {
        // Load AES key from file
        byte[] aesKey = CryptoUtils.loadAesKey("keys/aes_key1.b64");

        String plaintextStr = "This is a test message for AES-OCB!";
        byte[] plaintext = CryptoUtils.stringToBytes(plaintextStr);

        // Encrypt
        CryptoUtils.OcbResult result = CryptoUtils.encryptWithRandomIv(aesKey, plaintext);

        // Decrypt
        byte[] decrypted = CryptoUtils.aesOcbDecrypt(aesKey, result.iv, result.ciphertext);
        String decryptedStr = CryptoUtils.bytesToString(decrypted);

        if (!plaintextStr.equals(decryptedStr)) {
            throw new RuntimeException("AES-OCB encryption/decryption failed");
        } else {
            System.out.println("AES-OCB encryption/decryption test passed");
        }
    }
}
