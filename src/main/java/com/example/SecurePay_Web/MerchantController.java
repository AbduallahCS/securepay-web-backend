package com.example.SecurePay_Web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCrypt;

@RestController
@RequestMapping("/api/merchants")
public class MerchantController {

    @Autowired
    private MerchantRepository merchantRepository;

    // DTO for incoming request
    public static class MerchantRequest {
        public String name;
        public String email;
        public String password; // client sends plaintext, will hash before saving
    }
    // DTO for returning objects
    public static class MerchantResponse {
        public Long id;
        public String name;
        public String email;
        public String createdAt;

        public MerchantResponse(Merchant merchant) {
            this.id = merchant.getId();
            this.name = merchant.getName();
            this.email = merchant.getEmail();
            this.createdAt = merchant.getCreatedAt().toString();
        }
    }


    //@RequestBody tells Spring Boot to read the HTTP request body (JSON).
    //Spring Boot uses Jackson (built-in JSON library) to deserialize the JSON into a MerchantRequest object.
    @PostMapping
    public ResponseEntity<MerchantResponse> createMerchant(@RequestBody MerchantRequest request) {
        // 1. Optional: check if email already exists
        if (merchantRepository.findByEmail(request.email) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        // 2. Hash the password before saving
        String passwordHash = org.springframework.security.crypto.bcrypt.BCrypt
                .hashpw(request.password, org.springframework.security.crypto.bcrypt.BCrypt.gensalt());

        // 3. Create merchant entity
        Merchant merchant = new Merchant();
        merchant.setName(request.name);
        merchant.setEmail(request.email);
        merchant.setPasswordHash(passwordHash);

        // 4. Save in database
        Merchant saved = merchantRepository.save(merchant);

        // 5. Return 201 CREATED with the saved merchant
//        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
        return ResponseEntity.status(HttpStatus.CREATED).body(new MerchantResponse(saved));
    }
}
