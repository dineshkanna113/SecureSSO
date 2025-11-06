package com.example.finalsso.repository;

import com.example.finalsso.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    long countByUserRole(User.UserRole role);
    java.util.List<User> findByTenant_TenantId(Long tenantId);
    java.util.List<User> findByTenantIsNull(); // For SUPER_ADMIN users without tenant
}

