package com.accesshub.rag;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, UUID> {
    List<SecurityPolicy> findByTenantId(UUID tenantId);
    List<SecurityPolicy> findByTenantIdAndCategory(UUID tenantId, String category);
}
