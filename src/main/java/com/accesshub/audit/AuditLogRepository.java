package com.accesshub.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
    Page<AuditLog> findByTenantId(UUID tenantId, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.tenantId = :tenantId " +
           "AND (:action IS NULL OR a.action = :action) " +
           "AND (:actorId IS NULL OR a.actorId = :actorId)")
    Page<AuditLog> findByTenantIdFiltered(
            @Param("tenantId") UUID tenantId,
            @Param("action") String action,
            @Param("actorId") UUID actorId,
            Pageable pageable);

    List<AuditLog> findTop20ByTenantIdOrderByTimestampDesc(UUID tenantId);
}
