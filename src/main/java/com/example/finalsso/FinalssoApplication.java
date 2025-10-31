package com.example.finalsso;

import com.example.finalsso.entity.User;
import com.example.finalsso.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class FinalssoApplication {

	public static void main(String[] args) {
		SpringApplication.run(FinalssoApplication.class, args);
	}

    @Bean
    @Order(1)
    CommandLineRunner seedAdmin(UserRepository repo, PasswordEncoder encoder) {
        return args -> {
            repo.findByUsername("admin").ifPresentOrElse(existing -> {
                // Ensure the built-in admin always has ROLE_ADMIN and is enabled
                existing.setRole("ROLE_ADMIN");
                existing.setEnabled(true);
                if (existing.getPassword() == null || existing.getPassword().length() < 20) {
                    existing.setPassword(encoder.encode("admin123"));
                }
                repo.save(existing);
            }, () -> {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode("admin123"));
                admin.setEmail("admin@example.com");
                admin.setFirstName("System");
                admin.setLastName("Admin");
                admin.setRole("ROLE_ADMIN");
                admin.setEnabled(true);
                repo.save(admin);
            });
        };
    }
}
