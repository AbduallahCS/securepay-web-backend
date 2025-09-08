package com.example.SecurePay_Web.Controller;

import com.example.SecurePay_Web.Service.TransactionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/transactions")
public class TransactionController {

    @Autowired
    private TransactionService transactionService;

    @PostMapping
    public ResponseEntity<Map<String, Object>> createTransaction(
            @RequestBody Map<String, Object> payload,
            @RequestHeader("X-Signature") String hmac,
            @RequestHeader("X-Timestamp") long timestamp) {

        Map<String, Object> response = transactionService.processTransaction(payload, hmac, timestamp);
        return ResponseEntity.status(201).body(response);
    }
}
