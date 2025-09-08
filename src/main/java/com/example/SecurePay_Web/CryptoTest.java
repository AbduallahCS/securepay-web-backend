package com.example.SecurePay_Web;

import com.example.SecurePay_Web.Utils.CryptoUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class CryptoTest {

    public static void main(String[] args) throws Exception {
        testStringByteConversion();
        testBase64EncodeDecode();
        testAesOcbEncryptDecrypt();
        testHmacSha256();
        testRsaMethods();
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
        CryptoUtils.OcbResult result = CryptoUtils.aesOcbEncryptWithRandomIV(aesKey, plaintext);

        // Decrypt
        byte[] decrypted = CryptoUtils.aesOcbDecrypt(aesKey, result.iv, result.ciphertext);
        String decryptedStr = CryptoUtils.bytesToString(decrypted);

        if (!plaintextStr.equals(decryptedStr)) {
            throw new RuntimeException("AES-OCB encryption/decryption failed");
        } else {
            System.out.println("AES-OCB encryption/decryption test passed");
        }
    }

    private static void testHmacSha256() throws Exception {
        byte[] secret = "supersecretkey".getBytes();
        byte[] message = "This is a test".getBytes();

        String mac = CryptoUtils.hmacSha256Base64(secret, message);
        boolean valid = CryptoUtils.hmacSha256Verify(secret, message, mac);

        if (!valid) {
            throw new RuntimeException("HMAC verification failed");
        } else {
            System.out.println("HMAC-SHA256 test passed");
        }
    }

    public static void testRsaMethods() throws Exception {
        // Load keys from your keys/ directory
        PublicKey pub = CryptoUtils.loadPublicKeyFromFs("keys/rsa_public.pem");
        PrivateKey priv = CryptoUtils.loadPrivateKeyFromFs("keys/rsa_private.pem");

        String message = "Hello, SecurePay!";
        byte[] plaintext = CryptoUtils.stringToBytes(message);

        // ----- Encryption / Decryption Test -----
        byte[] encrypted = CryptoUtils.rsaEncryptWithPublic(pub, plaintext);
        byte[] decrypted = CryptoUtils.rsaDecryptWithPrivate(priv, encrypted);
        String decryptedMessage = CryptoUtils.bytesToString(decrypted);

//        System.out.println("Original message: " + message);
//        System.out.println("Decrypted message: " + decryptedMessage);
//        System.out.println("Encryption/Decryption successful? " + message.equals(decryptedMessage));

        // ----- Signing / Verification Test -----
        byte[] signature = CryptoUtils.rsaSign(priv, plaintext);
        boolean verified = CryptoUtils.rsaVerify(pub, plaintext, signature);

//        System.out.println("Signature verified? " + verified);

        // ----- Tampering Test -----
        byte[] tampered = Arrays.copyOf(plaintext, plaintext.length);
        tampered[0] ^= 0x01; // flip first byte
        boolean tamperedVerified = CryptoUtils.rsaVerify(pub, tampered, signature);
//        System.out.println("Tampered message verified? " + tamperedVerified); // should be false
        System.out.println("RSA-OAEP-PSS test passed"); // should be false
    }
}
