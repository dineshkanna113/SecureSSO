package com.accesshub.role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {
    List<Role> findByTenantId(UUID tenantId);
    Optional<Role> findByIdAndTenantId(UUID id, UUID tenantId);
    Optional<Role> findByNameAndTenantId(String name, UUID tenantId);
    boolean existsByNameAndTenantId(String name, UUID tenantId);
}
