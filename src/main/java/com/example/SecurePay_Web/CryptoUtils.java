package com.example.SecurePay_Web;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.IOException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {
    static {
        // Register BouncyCastle provider once
        Security.addProvider(new BouncyCastleProvider());
    }

    // ---------- String <-> byte[] ----------
    public static byte[] stringToBytes(String data_str) {
        return data_str.getBytes(StandardCharsets.UTF_8);
    }

    public static String bytesToString(byte[] data_bytes) {
        return new String(data_bytes, StandardCharsets.UTF_8);
    }

    // ---------- Base64 encode/decode ----------
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    // ---------- Load PEM Public Key ----------
    public static PublicKey loadPublicKey(String pemFilePath) throws Exception {
        String keyPem = new String(Files.readAllBytes(Paths.get(pemFilePath)), StandardCharsets.UTF_8);
        keyPem = keyPem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", ""); // remove newlines/spaces

        byte[] keyBytes = Base64.getDecoder().decode(keyPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    // ---------- Load PEM Private Key ----------
    public static PrivateKey loadPrivateKey(String pemFilePath) throws Exception {
        String keyPem = new String(Files.readAllBytes(Paths.get(pemFilePath)), StandardCharsets.UTF_8);
        keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    // ---------- Read Base64-encoded AES key ----------
    public static byte[] loadAesKey(String filePath) throws IOException {
        String base64Key = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        return Base64.getDecoder().decode(base64Key.trim());
    }


    // ---------- OCB helpers ----------
    // recommended IV/nonce length for OCB: 12..15 bytes (we'll use 12 by default)
    public static byte[] generateOcbIv(int lengthBytes) {
        if (lengthBytes < 1 || lengthBytes > 15) {
            throw new IllegalArgumentException("OCB nonce length must be between 1 and 15");
        }
        byte[] iv = new byte[lengthBytes];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt with AES/OCB/NoPadding using BouncyCastle provider.
     * @param key  AES key (16/24/32 bytes)
     * @param iv   nonce/iv (1..15 bytes recommended 12)
     * @param plaintext raw plaintext bytes
     * @return ciphertext (ciphertext || tag) as raw bytes
     */
    public static byte[] aesOcbEncrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes");
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        // tag length: 128 bits (16 bytes)
        AEADParameterSpec aeadSpec = new AEADParameterSpec(iv, 128);
        Cipher cipher = Cipher.getInstance("AES/OCB/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, aeadSpec);
        // If you have associated data: cipher.updateAAD(aad);
        return cipher.doFinal(plaintext); // returns ciphertext||tag
    }

    /**
     * Decrypt AES/OCB ciphertext.
     * @param key AES key
     * @param iv  nonce/iv used for encryption
     * @param ciphertext ciphertext with tag appended
     * @return decrypted plaintext bytes
     * @throws AEADBadTagException if authentication fails (tampering)
     */
    public static byte[] aesOcbDecrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes");
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        AEADParameterSpec aeadSpec = new AEADParameterSpec(iv, 128);
        Cipher cipher = Cipher.getInstance("AES/OCB/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, aeadSpec);
        // If you used associated data during encrypt: cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    // Small convenience wrapper to return iv + ciphertext together
    public static class OcbResult {
        public final byte[] iv;
        public final byte[] ciphertext;

        public OcbResult(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    /**
     * Convenience: encrypt with a freshly-generated 12-byte IV (recommended).
     */
    public static OcbResult encryptWithRandomIv(byte[] aesKey, byte[] plaintext) throws Exception {
        byte[] iv = generateOcbIv(12);
        byte[] ct = aesOcbEncrypt(aesKey, iv, plaintext);
        return new OcbResult(iv, ct);
    }

    /**
     * Compute HMAC-SHA256 of a message and return Base64-encoded MAC.
     * @param secret secret key as byte array
     * @param message message as byte array
     * @return Base64-encoded HMAC
     * @throws Exception
     */
    public static String hmacSha256Base64(byte[] secret, byte[] message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secret, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        byte[] macBytes = mac.doFinal(message);
        return Base64.getEncoder().encodeToString(macBytes);
    }

    /**
     * Verify a Base64-encoded HMAC-SHA256 against a message and secret.
     * @param secret secret key as byte array
     * @param message message as byte array
     * @param base64Mac Base64-encoded MAC to verify
     * @return true if MAC matches, false otherwise
     * @throws Exception
     */
    public static boolean hmacSha256Verify(byte[] secret, byte[] message, String base64Mac) throws Exception {
        String expectedMac = hmacSha256Base64(secret, message);
        // constant-time comparison to prevent timing attacks
        return constantTimeEquals(Base64.getDecoder().decode(base64Mac), Base64.getDecoder().decode(expectedMac));
    }

    /**
     * Constant-time comparison to avoid timing attacks
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
