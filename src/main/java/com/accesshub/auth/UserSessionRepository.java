package com.accesshub.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    Optional<UserSession> findBySessionIdentifier(String sessionIdentifier);
    List<UserSession> findByTenantIdAndUserIdAndActiveTrue(UUID tenantId, UUID userId);

    @Modifying
    @Query("UPDATE UserSession s SET s.active = false WHERE s.tenantId = :tenantId AND s.userId = :userId")
    void deactivateAllUserSessions(@Param("tenantId") UUID tenantId, @Param("userId") UUID userId);
}
