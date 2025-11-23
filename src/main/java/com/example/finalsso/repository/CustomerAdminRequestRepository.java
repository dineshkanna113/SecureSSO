package com.example.finalsso.repository;

import com.example.finalsso.entity.CustomerAdminRequest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CustomerAdminRequestRepository extends JpaRepository<CustomerAdminRequest, Long> {
    List<CustomerAdminRequest> findByStatus(CustomerAdminRequest.RequestStatus status);
    List<CustomerAdminRequest> findByStatusOrderByRequestedAtDesc(CustomerAdminRequest.RequestStatus status);
    boolean existsByEmail(String email);
    java.util.Optional<CustomerAdminRequest> findByEmail(String email);
}

