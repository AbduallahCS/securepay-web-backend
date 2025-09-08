package com.example.SecurePay_Web;

import com.example.SecurePay_Web.Entity.Merchant;
import com.example.SecurePay_Web.Repository.MerchantRepository;
import com.example.SecurePay_Web.Utils.CryptoUtils;
import com.example.SecurePay_Web.Utils.JsonUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)  // allows non-static @BeforeAll
public class TransactionServiceTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MerchantRepository merchantRepository;

    static String aes_key_str = "vSuw7xIFoP7D5L/ERxLdPCWpxkVeTjWKpgXLl/hIuig=";
    static String hmac_key_str = "4U2rXVjjuSfALEkRRTRzRL7l2NNhUuUveMIHlsKAfI4=";
    static byte[] aes_key_bytes = CryptoUtils.base64Decode(aes_key_str);
    static byte[] hmac_key_bytes = CryptoUtils.base64Decode(hmac_key_str);
    static Long merchantId = 2L;

    @BeforeAll
    void setupMerchant() {
        Merchant merchant = new Merchant();
        merchant.setId(merchantId);
        merchant.setName("Test Merchant");
        merchant.setEmail("test@example.com");
        merchant.setAesKeyBase64(aes_key_str);
        merchant.setHmacKeyBase64(hmac_key_str);
        merchant.setPasswordHash("testhash123"); // <- important
        merchantRepository.save(merchant);
    }

    @Test
    @DisplayName("Full Transaction Integration Test")
    void testTransactionEndpoint() throws Exception {
        // --- Build transaction JSON ---
        Map<String, Object> transactionMap = new HashMap<>();
        transactionMap.put("merchantId", merchantId);
        transactionMap.put("amount", 100);
        transactionMap.put("currency", "USD");
        transactionMap.put("pan", "123456789123456");

        // --- Encrypt PAN ---
        byte[] panBytes = CryptoUtils.stringToBytes((String) transactionMap.get("pan"));
        CryptoUtils.OcbResult panResult = CryptoUtils.aesOcbEncryptWithRandomIV(aes_key_bytes, panBytes);
        Map<String, String> panEncrypted = Map.of(
                "panCiphertext", CryptoUtils.base64Encode(panResult.ciphertext),
                "iv", CryptoUtils.base64Encode(panResult.iv)
        );
        transactionMap.put("pan", panEncrypted);

        // --- Compute HMAC ---
        String transactionJson = JsonUtils.mapToJson(transactionMap);
        String transactionHmac = CryptoUtils.hmacSha256Base64(hmac_key_bytes, transactionJson.getBytes(StandardCharsets.UTF_8));

        // --- Final request payload ---
        Map<String, Object> finalPayload = Map.of(
                "transaction", transactionMap,
                "hmac", transactionHmac
        );
        String finalPayloadJson = JsonUtils.mapToJson(finalPayload);

        long timestamp = System.currentTimeMillis();

        // --- Send POST to real controller ---
        String responseJson = mockMvc.perform(post("/api/transactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Signature", transactionHmac)
                        .header("X-Timestamp", timestamp)
                        .content(finalPayloadJson))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.transactionId").exists())
                .andExpect(jsonPath("$.status").value("CREATED"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        System.out.println("Server response: " + responseJson);

    }
}
