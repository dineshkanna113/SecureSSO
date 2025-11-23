package com.example.finalsso.service;

import com.example.finalsso.entity.CustomerAdminRequest;
import com.example.finalsso.entity.Tenant;
import com.example.finalsso.entity.User;
import com.example.finalsso.repository.CustomerAdminRequestRepository;
import com.example.finalsso.repository.TenantRepository;
import com.example.finalsso.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;

@Service
public class CustomerAdminRequestService {
    
    @Autowired
    private CustomerAdminRequestRepository requestRepository;
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private TenantRepository tenantRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    /**
     * Create a new customer admin request
     */
    @Transactional
    public CustomerAdminRequest createRequest(String firstName, String lastName, 
                                             String email, String companyName, 
                                             String username, String password,
                                             String message) {
        // Validate email format
        if (email == null || !email.matches(".+@.+\\..+")) {
            throw new IllegalArgumentException("Invalid email address.");
        }
        
        // Validate company name doesn't already exist
        if (tenantRepository.existsByTenantName(companyName.trim())) {
            throw new IllegalArgumentException("A company with this name already exists. Please use a different company name.");
        }
        
        // Validate username if provided
        if (username != null && !username.trim().isEmpty()) {
            String usernameLower = username.trim().toLowerCase();
            if (usernameLower.length() < 4) {
                throw new IllegalArgumentException("Username must be at least 4 characters long.");
            }
            if (!usernameLower.matches("^[a-z0-9_]+$")) {
                throw new IllegalArgumentException("Username must be lowercase and contain only letters, numbers, and underscores.");
            }
            if (userRepository.findByUsername(usernameLower).isPresent()) {
                throw new IllegalArgumentException("Username already exists. Please choose another.");
            }
            username = usernameLower;
        }
        
        // Validate password if provided
        if (password != null && !password.trim().isEmpty()) {
            if (password.length() < 6 || password.length() > 10) {
                throw new IllegalArgumentException("Password must be between 6 and 10 characters.");
            }
        }
        
        CustomerAdminRequest request = new CustomerAdminRequest();
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setEmail(email);
        request.setCompanyName(companyName);
        request.setRequestedUsername(username);
        request.setRequestedPassword(password); // Store plain password temporarily, will be encrypted on approval
        request.setMessage(message);
        request.setStatus(CustomerAdminRequest.RequestStatus.PENDING);
        
        return requestRepository.save(request);
    }
    
    /**
     * Approve a request and create customer admin user
     */
    @Transactional
    public void approveRequest(Long requestId, String reviewedBy, String reviewNotes) {
        CustomerAdminRequest request = requestRepository.findById(requestId)
            .orElseThrow(() -> new IllegalArgumentException("Request not found"));
        
        if (request.getStatus() != CustomerAdminRequest.RequestStatus.PENDING) {
            throw new IllegalArgumentException("Request has already been reviewed");
        }
        
        request.setStatus(CustomerAdminRequest.RequestStatus.APPROVED);
        request.setReviewedAt(java.time.LocalDateTime.now());
        request.setReviewedBy(reviewedBy);
        request.setReviewNotes(reviewNotes);
        requestRepository.save(request);
        
        // Find or create tenant
        Tenant tenant = tenantRepository.findByTenantNameIgnoreCase(request.getCompanyName())
            .orElseGet(() -> {
                Tenant newTenant = new Tenant();
                newTenant.setTenantName(request.getCompanyName());
                newTenant.setCreatedBy(reviewedBy);
                newTenant.setActive(true);
                return tenantRepository.save(newTenant);
            });
        
        // Use requested username/password if provided, otherwise generate
        String username;
        String password;
        
        if (request.getRequestedUsername() != null && !request.getRequestedUsername().trim().isEmpty()) {
            // Use requested username
            username = request.getRequestedUsername().trim().toLowerCase();
            // Verify it's still available
            if (userRepository.findByUsername(username).isPresent()) {
                throw new IllegalArgumentException("The requested username is no longer available. Please contact support.");
            }
        } else {
            // Generate username from email (before @ symbol)
            String emailLocalPart = request.getEmail().split("@")[0].toLowerCase()
                .replaceAll("[^a-z0-9]", "");
            if (emailLocalPart.length() < 4) {
                emailLocalPart = emailLocalPart + "user";
            }
            String baseUsername = emailLocalPart.substring(0, Math.min(8, emailLocalPart.length()));
            username = baseUsername;
            int counter = 1;
            while (userRepository.findByUsername(username).isPresent()) {
                username = baseUsername + counter;
                counter++;
                // Prevent infinite loop
                if (counter > 1000) {
                    username = baseUsername + System.currentTimeMillis() % 10000;
                    break;
                }
            }
        }
        
        if (request.getRequestedPassword() != null && !request.getRequestedPassword().trim().isEmpty()) {
            // Use requested password
            password = request.getRequestedPassword();
        } else {
            // Generate random password (8 characters)
            password = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        }
        
        // Create customer admin user
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(passwordEncoder.encode(password));
        newUser.setEmail(request.getEmail());
        newUser.setFirstName(request.getFirstName());
        newUser.setLastName(request.getLastName());
        newUser.setUserRole(User.UserRole.CUSTOMER_ADMIN);
        newUser.setTenant(tenant);
        newUser.setEnabled(true);
        userRepository.save(newUser);
        
        // Send approval email with credentials
        try {
            String subject = "Your Admin Access Request Has Been Approved";
            String body = String.format(
                "Dear %s %s,\n\n" +
                "Your request for admin access to %s has been approved!\n\n" +
                "Your account has been created with the following credentials:\n\n" +
                "Username: %s\n" +
                "Password: %s\n\n" +
                "Please log in at: http://localhost:8080/login\n\n" +
                "IMPORTANT: Please change your password after your first login for security.\n\n" +
                "Best regards,\n" +
                "SSO Application Team",
                request.getFirstName(), request.getLastName(), request.getCompanyName(),
                username, password
            );
            emailService.sendEmail(request.getEmail(), subject, body);
        } catch (Exception e) {
            // Log error but don't fail the approval
            e.printStackTrace();
        }
    }
    
    /**
     * Reject a request
     */
    @Transactional
    public void rejectRequest(Long requestId, String reviewedBy, String reviewNotes) {
        CustomerAdminRequest request = requestRepository.findById(requestId)
            .orElseThrow(() -> new IllegalArgumentException("Request not found"));
        
        if (request.getStatus() != CustomerAdminRequest.RequestStatus.PENDING) {
            throw new IllegalArgumentException("Request has already been reviewed");
        }
        
        request.setStatus(CustomerAdminRequest.RequestStatus.REJECTED);
        request.setReviewedAt(java.time.LocalDateTime.now());
        request.setReviewedBy(reviewedBy);
        request.setReviewNotes(reviewNotes);
        requestRepository.save(request);
        
        // Send rejection email
        try {
            String subject = "Your Admin Access Request";
            String body = String.format(
                "Dear %s %s,\n\n" +
                "Thank you for your interest. Unfortunately, your request for admin access to %s has been declined.\n\n" +
                (reviewNotes != null && !reviewNotes.trim().isEmpty() ? 
                    "Reason: " + reviewNotes + "\n\n" : "") +
                "If you have any questions, please contact support.\n\n" +
                "Best regards,\n" +
                "SSO Application Team",
                request.getFirstName(), request.getLastName(), request.getCompanyName()
            );
            emailService.sendEmail(request.getEmail(), subject, body);
        } catch (Exception e) {
            // Log error but don't fail the rejection
            e.printStackTrace();
        }
    }
}

