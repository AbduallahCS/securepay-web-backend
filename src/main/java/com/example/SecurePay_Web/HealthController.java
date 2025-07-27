package com.example.SecurePay_Web;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import javax.sql.DataSource;
import java.sql.Connection;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {

    @Autowired
    private DataSource dataSource;

    @GetMapping("/health")
    public Map<String, String> healthCheck() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "OK");

        try (Connection conn = dataSource.getConnection()) {
            if (conn.isValid(1)) {
                response.put("db", "Connected");
                //System.out.println("Connected to database successfully");
            } else {
                response.put("db", "Disconnected");
            }
        } catch (Exception e) {
            response.put("db", "Error");
        }

        return response;
    }
}
