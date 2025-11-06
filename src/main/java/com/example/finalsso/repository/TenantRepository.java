package com.example.finalsso.repository;

import com.example.finalsso.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {
    Optional<Tenant> findByTenantName(String tenantName);
    boolean existsByTenantName(String tenantName);
}


