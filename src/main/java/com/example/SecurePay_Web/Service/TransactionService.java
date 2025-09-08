package com.example.SecurePay_Web.Service;

import com.example.SecurePay_Web.Entity.Merchant;
import com.example.SecurePay_Web.Entity.Transaction;
import com.example.SecurePay_Web.Repository.MerchantRepository;
import com.example.SecurePay_Web.Repository.TransactionRepository;
import com.example.SecurePay_Web.Utils.CryptoUtils;
import com.example.SecurePay_Web.Utils.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class TransactionService {

    @Autowired
    private MerchantRepository merchantRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    private static final long TIMESTAMP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

    public Map<String, Object> processTransaction(Map<String, Object> payloadMap, String hmacBase64, long timestamp) {
        try {
            // --- Step 1: Verify timestamp ---
            long now = Instant.now().toEpochMilli();
            if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_MS) {
                throw new RuntimeException("Timestamp out of window");
            }

            // --- Step 2: Extract merchantId ---
            Map<String, Object> transactionData = (Map<String, Object>) payloadMap.get("transaction");
            Long merchantId = Long.parseLong(transactionData.get("merchantId").toString());

            // --- Step 3: Load AES/HMAC keys ---
            Merchant merchant = merchantRepository.findById(merchantId)
                    .orElseThrow(() -> new RuntimeException("Merchant not found"));
            byte[] aesKey = Base64.getDecoder().decode(merchant.getAesKeyBase64());
            byte[] hmacKey = Base64.getDecoder().decode(merchant.getHmacKeyBase64());

            // --- Step 4: Verify HMAC ---
            String jsonString = JsonUtils.mapToJson(transactionData);
            boolean validHmac = CryptoUtils.hmacSha256Verify(hmacKey, jsonString.getBytes(StandardCharsets.UTF_8), hmacBase64);
            if (!validHmac) {
                throw new RuntimeException("Invalid HMAC");
            }

            // --- Step 5: Decrypt PAN ---
            Map<String, String> panEncrypted = (Map<String, String>) transactionData.get("pan");
            byte[] panCiphertext = Base64.getDecoder().decode(panEncrypted.get("panCiphertext"));
            byte[] iv = Base64.getDecoder().decode(panEncrypted.get("iv"));
            byte[] panBytes = CryptoUtils.aesOcbDecrypt(aesKey, iv, panCiphertext);
            String pan = new String(panBytes, StandardCharsets.UTF_8);

            // --- Step 6: Compute last 4 digits ---
            String panLast4 = pan.substring(pan.length() - 4);

            // --- Step 7: Save transaction ---
            Transaction tx = new Transaction();
            tx.setMerchantId(merchantId);
            tx.setAmount(Double.parseDouble(transactionData.get("amount").toString()));
            tx.setCurrency(transactionData.get("currency").toString());
            tx.setStatus("CREATED"); // <-- must set non-null value
            tx.setPanCiphertext(panEncrypted.get("panCiphertext"));
            tx.setPanIv(panEncrypted.get("iv"));
            tx.setPanLast4(panLast4);
            transactionRepository.save(tx);

            // --- Step 8: Build response ---
            Map<String, Object> response = new HashMap<>();
            response.put("transactionId", tx.getId());
            response.put("status", "CREATED");

            return response;

        } catch (Exception e) {
            throw new RuntimeException("Transaction processing failed: " + e.getMessage(), e);
        }
    }
}
