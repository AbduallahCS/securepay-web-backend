package com.example.SecurePay_Web;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MerchantRepository extends JpaRepository<Merchant, Long> {
    // Optional: find merchant by email
    Merchant findByEmail(String email);
}
