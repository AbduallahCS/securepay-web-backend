package com.example.SecurePay_Web.Controller;

import com.example.SecurePay_Web.Service.MerchantKeyExchangeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/keys/exchange")
public class MerchantKeyExchangeController {

    @Autowired
    private MerchantKeyExchangeService keyExchangeService;

    public static class KeyExchangeRequest {
        public String ciphertext;
        public String signature;
    }

    public static class KeyExchangeResponse {
        public String ciphertext;
        public String signature;

        public KeyExchangeResponse(String ciphertext, String signature) {
            this.ciphertext = ciphertext;
            this.signature = signature;
        }
    }

    @PostMapping("/request")
    public ResponseEntity<Map<String, Object>> requestKeys(@RequestBody KeyExchangeRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            response = keyExchangeService.processRequest(request.ciphertext, request.signature);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace(); // logs full stack trace
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }
}
