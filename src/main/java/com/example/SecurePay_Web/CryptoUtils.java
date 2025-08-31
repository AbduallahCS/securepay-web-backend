package com.example.SecurePay_Web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

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
}
