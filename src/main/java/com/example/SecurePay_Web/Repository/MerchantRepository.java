package com.example.SecurePay_Web.Repository;

import com.example.SecurePay_Web.Entity.Merchant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MerchantRepository extends JpaRepository<Merchant, Long> {
    // Optional: find merchant by email
    Merchant findByEmail(String email);
}
