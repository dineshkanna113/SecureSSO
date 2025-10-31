package com.example.finalsso.repository;

import com.example.finalsso.entity.SSOProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SSOProviderRepository extends JpaRepository<SSOProvider, Long> {
    boolean existsByNameIgnoreCase(String name);
    Optional<SSOProvider> findByNameIgnoreCase(String name);
}


