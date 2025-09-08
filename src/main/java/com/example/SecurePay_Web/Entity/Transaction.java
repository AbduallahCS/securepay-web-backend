package com.example.SecurePay_Web.Entity;

import jakarta.persistence.*;

@Entity
@Table(name = "transactions")
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "merchant_id", nullable = false)
    private Long merchantId;

    @Column(nullable = false)
    private Double amount;

    @Column(nullable = false)
    private String currency;

    @Column(name = "pan_last4", length = 4, nullable = false)
    private String panLast4;

    @Column(name = "status")
    private String status;

    @Column(name = "pan_ciphertext")
    private String panCiphertext;

    @Column(name = "pan_iv")
    private String panIv;

    public Transaction() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getMerchantId() {
        return merchantId;
    }

    public void setMerchantId(Long merchantId) {
        this.merchantId = merchantId;
    }

    public Double getAmount() {
        return amount;
    }

    public void setAmount(Double amount) {
        this.amount = amount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public String getPanLast4() {
        return panLast4;
    }

    public void setPanLast4(String panLast4) {
        this.panLast4 = panLast4;
    }


    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }


    public String getPanCiphertext() {
        return panCiphertext;
    }

    public void setPanCiphertext(String panCiphertext) {
        this.panCiphertext = panCiphertext;
    }


    public String getPanIv() {
        return panIv;
    }

    public void setPanIv(String panIv) {
        this.panIv = panIv;
    }
}
