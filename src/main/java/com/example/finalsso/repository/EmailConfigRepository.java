package com.example.finalsso.repository;

import com.example.finalsso.entity.EmailConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailConfigRepository extends JpaRepository<EmailConfig, Long> {
    // Only one email config should exist
    EmailConfig findFirstByOrderByIdAsc();
}

