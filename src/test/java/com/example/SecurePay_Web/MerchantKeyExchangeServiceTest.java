package com.example.SecurePay_Web;

import com.example.SecurePay_Web.Entity.Merchant;
import com.example.SecurePay_Web.Repository.MerchantRepository;
import com.example.SecurePay_Web.Service.MerchantKeyExchangeService;
import com.example.SecurePay_Web.Utils.CryptoUtils;
import com.example.SecurePay_Web.Utils.JsonUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class MerchantKeyExchangeServiceTest {

    @Autowired
    private MerchantKeyExchangeService keyExchangeService;

    @Mock
    private MerchantRepository merchantRepository;

    // --- Server keys ---
    static PrivateKey serverPrivateKey;
    static PublicKey serverPublicKey;
    // --- Client keys ---
    static PrivateKey clientPrivateKey;
    static PublicKey clientPublicKey;

    @BeforeAll
    static void setupKeys() throws Exception {
        String basePath = "../SecurePay-Web/keys/";

        // --- Server keys ---
        serverPrivateKey = CryptoUtils.loadPrivateKeyFromFs(basePath + "rsa_private.pem");
        serverPublicKey  = CryptoUtils.loadPublicKeyFromFs(basePath + "rsa_public.pem");

        // --- Client keys ---
        clientPrivateKey = CryptoUtils.loadPrivateKeyFromFs(basePath + "client_rsa_private.pem");
        clientPublicKey  = CryptoUtils.loadPublicKeyFromFs(basePath + "client_rsa_public.pem");
    }

    @Test
    @DisplayName("Full key exchange flow: client → server → client")
    void testFullKeyExchangeFlow() throws Exception {
        // --- Simulate frontend 3A ---
        long merchantId = 2L;

        byte[] nonce_bytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce_bytes);
        String nonce = Base64.getEncoder().encodeToString(nonce_bytes);

        String rawJson = String.format(
                "{\"merchantId\": %d, \"nonce\": \"%s\", \"timestamp\": %d}",
                merchantId, nonce, System.currentTimeMillis()
        );

        // Encrypt raw JSON with server public key
        byte[] ciphertext = CryptoUtils.rsaEncryptWithPublic(serverPublicKey,
                rawJson.getBytes(StandardCharsets.UTF_8));

        // Sign ciphertext with client private key
        byte[] signature = CryptoUtils.rsaSign(clientPrivateKey, ciphertext);

        String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);
        String signatureB64 = Base64.getEncoder().encodeToString(signature);

        // --- Mock repository (Step 7) ---
        Merchant merchant = new Merchant();
        merchant.setId(merchantId);
        Mockito.when(merchantRepository.findById(merchantId)).thenReturn(Optional.of(merchant));

        // --- Call backend service ---
        Map<String, Object> response = keyExchangeService.processRequest(ciphertextB64, signatureB64);

        assertTrue(response.containsKey("ciphertext-as-json"));
        assertTrue(response.containsKey("signature-base64"));

        String encryptedMsgJson = response.get("ciphertext-as-json").toString();
        String serverSigB64 = response.get("signature-base64").toString();

        // --- Simulate frontend 3B ---
        // 1. Verify server signature
        byte[] serverSig = Base64.getDecoder().decode(serverSigB64);
        boolean verified = CryptoUtils.rsaVerify(serverPublicKey,
                encryptedMsgJson.getBytes(StandardCharsets.UTF_8), serverSig);

        assertTrue(verified, "Server signature must verify with server public key");

        // 2. Parse ciphertext-as-json
        Map<String, Object> encryptedMsgMap = JsonUtils.jsonToMap(encryptedMsgJson);
        Map<String, String> aesPart = (Map<String, String>) encryptedMsgMap.get("aes");

        String wrappedKeyB64 = encryptedMsgMap.get("rsaEncryptedKeyBase64").toString();
        String ctB64 = aesPart.get("ciphertextBase64");
        String ivB64 = aesPart.get("ivBase64");

        // 3. Decrypt session AES key with client private key
        byte[] sessionKey = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey,
                Base64.getDecoder().decode(wrappedKeyB64));

        // 4. Decrypt AES ciphertext
        byte[] decryptedPayload = CryptoUtils.aesOcbDecrypt(
                sessionKey,
                Base64.getDecoder().decode(ivB64),
                Base64.getDecoder().decode(ctB64)
        );
        String decryptedJson = new String(decryptedPayload, StandardCharsets.UTF_8);

        System.out.println("Decrypted final payload: " + decryptedJson);

        Map<String, Object> payloadMap = JsonUtils.jsonToMap(decryptedJson);

        // --- Assertions ---
        assertEquals(merchantId, Long.parseLong(payloadMap.get("merchantId").toString()));
        assertEquals(nonce, payloadMap.get("nonce").toString());
        assertTrue(payloadMap.containsKey("aesKeyBase64"));
        assertTrue(payloadMap.containsKey("hmacKeyBase64"));
        assertTrue(payloadMap.containsKey("issuedAt"));
    }
}
