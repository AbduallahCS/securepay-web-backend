package com.example.SecurePay_Web.Repository;

import com.example.SecurePay_Web.Entity.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TransactionRepository extends JpaRepository<Transaction, Long> {
}
