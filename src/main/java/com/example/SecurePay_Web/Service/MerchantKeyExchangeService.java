package com.example.SecurePay_Web.Service;

import com.example.SecurePay_Web.Utils.CryptoUtils;
import com.example.SecurePay_Web.Utils.JsonUtils;
import com.example.SecurePay_Web.Entity.Merchant;
import com.example.SecurePay_Web.Repository.MerchantRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class MerchantKeyExchangeService {

    @Autowired
    private MerchantRepository merchantRepository;

//    "/SecurePay-Web/keys/rsa_private.pem"
    private static final String SERVER_PRIVATE_KEY_PATH = "keys/rsa_private.pem";
    private static final String CLIENT_PUBLIC_KEY_PATH = "keys/client_rsa_public.pem";

    public Map<String, Object> processRequest(String ciphertextBase64, String signatureBase64) throws Exception {
        PrivateKey serverPrivateKey;
        PublicKey clientPublicKey;
        byte[] ciphertext;
        byte[] signature;
        byte[] decryptedBytes;
        String decryptedJson;
        Map<String, Object> requestMap;
        Long merchantId;
        String nonceEcho;
        byte[] aesKey = new byte[32];
        byte[] hmacKey = new byte[32];
        String aesBase64;
        String hmacBase64;
        Merchant merchant;
        Map<String, Object> payload;
        String payloadJson;
        byte[] encryptedPayload;
        String encryptedPayloadBase64;
        byte[] serverSig;
        String signatureBase64Resp;

        // --- Step 1: Load keys ---
        try {
            serverPrivateKey = CryptoUtils.loadPrivateKeyFromFs(SERVER_PRIVATE_KEY_PATH);
            clientPublicKey = CryptoUtils.loadPublicKeyFromFs(CLIENT_PUBLIC_KEY_PATH);
        } catch (Exception e) {
            throw new Exception("Step 1: Failed to load keys: " + e.getMessage(), e);
        }

        // --- Step 2: Base64 decode ---
        try {
            ciphertext = Base64.getDecoder().decode(ciphertextBase64);
            signature = Base64.getDecoder().decode(signatureBase64);
        } catch (Exception e) {
            throw new Exception("Step 2: Failed to decode Base64: " + e.getMessage(), e);
        }

        // --- Step 3: Verify client signature ---
        try {
            boolean verified = CryptoUtils.rsaVerify(clientPublicKey, ciphertext, signature);
            if (!verified) throw new RuntimeException("Client signature verification failed");
        } catch (Exception e) {
            throw new Exception("Step 3: Signature verification failed: " + e.getMessage(), e);
        }

        // --- Step 4: Decrypt ciphertext ---
        try {
            decryptedBytes = CryptoUtils.rsaDecryptWithPrivate(serverPrivateKey, ciphertext);
            decryptedJson = new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new Exception("Step 4: Failed to decrypt ciphertext: " + e.getMessage(), e);
        }

        // --- Step 5: Parse JSON ---
        try {
            requestMap = JsonUtils.jsonToMap(decryptedJson);
            if (!requestMap.containsKey("merchantId") || !requestMap.containsKey("nonce")) {
                throw new RuntimeException("Missing merchantId or nonce");
            }
            merchantId = Long.parseLong(requestMap.get("merchantId").toString());
            nonceEcho = requestMap.get("nonce").toString();
        } catch (Exception e) {
            throw new Exception("Step 5: Failed to parse request JSON: " + e.getMessage(), e);
        }

        // --- Step 6: Generate AES/HMAC keys ---
        try {
            new SecureRandom().nextBytes(aesKey);
            new SecureRandom().nextBytes(hmacKey);
            aesBase64 = Base64.getEncoder().encodeToString(aesKey);
            hmacBase64 = Base64.getEncoder().encodeToString(hmacKey);
        } catch (Exception e) {
            throw new Exception("Step 6: Failed to generate AES/HMAC keys: " + e.getMessage(), e);
        }

        // --- Step 7: Store keys in merchant entity ---
        try {
            merchant = merchantRepository.findById(merchantId)
                    .orElseThrow(() -> new RuntimeException("Merchant not found with id=" + merchantId));
            merchant.setAesKeyBase64(aesBase64);
            merchant.setHmacKeyBase64(hmacBase64);
            merchantRepository.save(merchant);
        } catch (Exception e) {
            throw new Exception("Step 7: Failed to store keys in merchant entity: " + e.getMessage(), e);
        }

        // --- Step 8: Prepare delivery payload ---
        try {
            payload = new HashMap<>();
            payload.put("merchantId", merchantId);
            payload.put("aesKeyBase64", aesBase64);
            payload.put("hmacKeyBase64", hmacBase64);
            payload.put("issuedAt", Instant.now().toString());
            payload.put("nonce", nonceEcho);
            payloadJson = JsonUtils.mapToJson(payload);
        } catch (Exception e) {
            throw new Exception("Step 8: Failed to prepare delivery payload: " + e.getMessage(), e);
        }

//        // --- Step 9: Encrypt payload with client public key ---
//        try {
//            encryptedPayload = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, payloadJson.getBytes(StandardCharsets.UTF_8));
//            encryptedPayloadBase64 = Base64.getEncoder().encodeToString(encryptedPayload);
//        } catch (Exception e) {
//            throw new Exception("Step 9: Failed to encrypt payload: " + e.getMessage(), e);
//        }
        // --- Step 9: Hybrid encrypt payload (AES-OCB + RSA-OAEP wrap) ---
        String encryptedMsgJson;  // we'll sign this exact JSON string
        try {
            // 9.1 Generate fresh random AES key k (32 bytes)
            byte[] sessionAesKey = new byte[32];
            new SecureRandom().nextBytes(sessionAesKey);

            // 9.2 AES-OCB encrypt RAW JSON
            CryptoUtils.OcbResult ocb = CryptoUtils.aesOcbEncryptWithRandomIV(
                    sessionAesKey,
                    payloadJson.getBytes(StandardCharsets.UTF_8)
            );
            String ctB64 = Base64.getEncoder().encodeToString(ocb.ciphertext);
            String ivB64 = Base64.getEncoder().encodeToString(ocb.iv);

            // 9.3 Wrap the AES key k with client's RSA public key (OAEP-SHA256)
            byte[] wrappedKey = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, sessionAesKey);
            String wrappedKeyB64 = Base64.getEncoder().encodeToString(wrappedKey);

            // 9.4 Build nested JSON: encrypted_msg = { aes: {...}, rsaEncryptedKeyBase64: "...", alg: "..." }
            Map<String, Object> encryptedMsg = new java.util.LinkedHashMap<>();
            Map<String, String> aesPart = new java.util.LinkedHashMap<>();
            aesPart.put("ciphertextBase64", ctB64);
            aesPart.put("ivBase64", ivB64);
            encryptedMsg.put("aes", aesPart);
            encryptedMsg.put("rsaEncryptedKeyBase64", wrappedKeyB64);
//            encryptedMsg.put("alg", "AES-256-OCB + RSA-OAEP-256"); // optional but helpful

            // 9.5 Serialize encrypted_msg JSON (this is what we will sign)
            encryptedMsgJson = JsonUtils.mapToJson(encryptedMsg);


        } catch (Exception e) {
            throw new Exception("Step 9: Failed to hybrid-encrypt payload: " + e.getMessage(), e);
        }


        // --- Step 10: Sign payload with server private key ---
        try {
            encryptedPayload = encryptedMsgJson.getBytes(StandardCharsets.UTF_8);
            encryptedPayloadBase64 = Base64.getEncoder().encodeToString(encryptedPayload);


            serverSig = CryptoUtils.rsaSign(serverPrivateKey, encryptedPayload);
            signatureBase64Resp = Base64.getEncoder().encodeToString(serverSig);
        } catch (Exception e) {
            throw new Exception("Step 10: Failed to sign payload: " + e.getMessage(), e);
        }

        Map<String, Object> finalPayload = new java.util.LinkedHashMap<>();
        finalPayload.put("ciphertext-as-json", encryptedMsgJson);
        finalPayload.put("signature-base64", signatureBase64Resp);
        return finalPayload;
    }
}
