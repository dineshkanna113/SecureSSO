package com.example.finalsso.repository;

import com.example.finalsso.entity.SSOProvider;
import com.example.finalsso.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SSOProviderRepository extends JpaRepository<SSOProvider, Long> {
    boolean existsByNameIgnoreCaseAndTenant(String name, Tenant tenant);
    Optional<SSOProvider> findByNameIgnoreCaseAndTenant(String name, Tenant tenant);
    List<SSOProvider> findByTenant(Tenant tenant);
    List<SSOProvider> findByTenantIsNull(); // Global providers (super admin)
    void deleteByTenant(Tenant tenant);
}


