package com.accesshub.application;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ApplicationRepository extends JpaRepository<Application, UUID> {
    Page<Application> findByTenantId(UUID tenantId, Pageable pageable);
    Optional<Application> findByIdAndTenantId(UUID id, UUID tenantId);
    Optional<Application> findByClientId(String clientId);
    boolean existsByClientId(String clientId);
}
