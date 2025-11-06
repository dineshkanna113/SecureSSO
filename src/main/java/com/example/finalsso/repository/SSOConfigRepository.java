package com.example.finalsso.repository;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SSOConfigRepository extends JpaRepository<SSOConfig, Long> {
    Optional<SSOConfig> findByTenant(Tenant tenant);
    Optional<SSOConfig> findByTenantIsNull(); // Global config (super admin)
}


