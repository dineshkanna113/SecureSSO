package com.example.finalsso.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "customer_admin_requests")
public class CustomerAdminRequest {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String firstName;
    
    @Column(nullable = false)
    private String lastName;
    
    @Column(nullable = false)
    private String email;
    
    @Column(nullable = false)
    private String companyName;
    
    @Column
    private String requestedUsername; // Username requested by user
    
    @Column
    private String requestedPassword; // Password requested by user (will be encrypted before approval)
    
    @Column(length = 1000)
    private String message; // Optional message from requester
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequestStatus status = RequestStatus.PENDING;
    
    @Column(nullable = false, updatable = false)
    private LocalDateTime requestedAt = LocalDateTime.now();
    
    private LocalDateTime reviewedAt;
    
    @Column(length = 500)
    private String reviewNotes; // Notes from super-admin
    
    private String reviewedBy; // Username of super-admin who reviewed
    
    public enum RequestStatus {
        PENDING, APPROVED, REJECTED
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getFirstName() {
        return firstName;
    }
    
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }
    
    public String getLastName() {
        return lastName;
    }
    
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public String getCompanyName() {
        return companyName;
    }
    
    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public RequestStatus getStatus() {
        return status;
    }
    
    public void setStatus(RequestStatus status) {
        this.status = status;
    }
    
    public LocalDateTime getRequestedAt() {
        return requestedAt;
    }
    
    public void setRequestedAt(LocalDateTime requestedAt) {
        this.requestedAt = requestedAt;
    }
    
    public LocalDateTime getReviewedAt() {
        return reviewedAt;
    }
    
    public void setReviewedAt(LocalDateTime reviewedAt) {
        this.reviewedAt = reviewedAt;
    }
    
    public String getReviewNotes() {
        return reviewNotes;
    }
    
    public void setReviewNotes(String reviewNotes) {
        this.reviewNotes = reviewNotes;
    }
    
    public String getReviewedBy() {
        return reviewedBy;
    }
    
    public void setReviewedBy(String reviewedBy) {
        this.reviewedBy = reviewedBy;
    }
    
    public String getRequestedUsername() {
        return requestedUsername;
    }
    
    public void setRequestedUsername(String requestedUsername) {
        this.requestedUsername = requestedUsername;
    }
    
    public String getRequestedPassword() {
        return requestedPassword;
    }
    
    public void setRequestedPassword(String requestedPassword) {
        this.requestedPassword = requestedPassword;
    }
}

