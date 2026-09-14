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
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);
    List<RefreshToken> findByTokenFamily(String tokenFamily);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true, r.revokedReason = :reason WHERE r.tokenFamily = :family")
    void revokeTokenFamily(@Param("family") String family, @Param("reason") String reason);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true, r.revokedReason = :reason WHERE r.tenantId = :tenantId AND r.userId = :userId")
    void revokeAllUserTokens(@Param("tenantId") UUID tenantId, @Param("userId") UUID userId, @Param("reason") String reason);
}
