package com.example.finalsso.service;

import com.example.finalsso.entity.EmailConfig;
import com.example.finalsso.repository.EmailConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;

import java.util.Properties;

@Service
public class EmailService {
    
    @Autowired
    private EmailConfigRepository emailConfigRepository;
    
    private JavaMailSender mailSender;
    
    /**
     * Initialize or reload mail sender from configuration
     */
    private void initializeMailSender() {
        EmailConfig config = emailConfigRepository.findFirstByOrderByIdAsc();
        if (config == null) {
            throw new IllegalStateException("Email configuration not found. Please configure email settings in super-admin panel.");
        }
        
        JavaMailSenderImpl mailSenderImpl = new JavaMailSenderImpl();
        mailSenderImpl.setHost(config.getHost());
        mailSenderImpl.setPort(config.getPort());
        mailSenderImpl.setUsername(config.getUsername());
        mailSenderImpl.setPassword(config.getPassword());
        
        Properties props = mailSenderImpl.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", config.getTls() ? "true" : "false");
        props.put("mail.smtp.ssl.enable", config.getSsl() ? "true" : "false");
        props.put("mail.debug", "false");
        
        this.mailSender = mailSenderImpl;
    }
    
    /**
     * Send email
     */
    public void sendEmail(String to, String subject, String body) {
        try {
            if (mailSender == null) {
                initializeMailSender();
            }
            
            EmailConfig config = emailConfigRepository.findFirstByOrderByIdAsc();
            String fromEmail = config.getFromEmail() != null ? config.getFromEmail() : config.getUsername();
            String fromName = config.getFromName() != null ? config.getFromName() : "SSO Application";
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromName + " <" + fromEmail + ">");
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            
            mailSender.send(message);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
        }
    }
    
    /**
     * Reload mail sender configuration (call after updating email config)
     */
    public void reloadConfiguration() {
        this.mailSender = null;
        initializeMailSender();
    }
}

