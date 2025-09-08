package com.example.SecurePay_Web.Entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "merchants")
public class Merchant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    // Optional for step 1: AES/HMAC keys
    @Column(name = "aes_key_base64")
    private String aesKeyBase64;

    @Column(name = "hmac_key_base64")
    private String hmacKeyBase64;

    // --- Getters and Setters ---
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public String getAesKeyBase64() { return aesKeyBase64; }
    public void setAesKeyBase64(String aesKeyBase64) { this.aesKeyBase64 = aesKeyBase64; }

    public String getHmacKeyBase64() { return hmacKeyBase64; }
    public void setHmacKeyBase64(String hmacKeyBase64) { this.hmacKeyBase64 = hmacKeyBase64; }
}
