package com.example.finalsso.controller.api;

import com.example.finalsso.entity.User;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.repository.TenantRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UsersApiController {

	private final UserRepository repo;
	private final PasswordEncoder encoder;
	private final TenantRepository tenantRepository;

	public UsersApiController(UserRepository repo, PasswordEncoder encoder, TenantRepository tenantRepository) {
		this.repo = repo;
		this.encoder = encoder;
		this.tenantRepository = tenantRepository;
	}

	@GetMapping
	public List<User> list() { return repo.findAll(); }

	@GetMapping("/{id}")
	public ResponseEntity<User> get(@PathVariable Long id) {
		return repo.findById(id).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
	}

	@GetMapping("/exists")
	public java.util.Map<String, Object> exists(@RequestParam String username, @RequestParam(required = false) Long excludeId) {
		boolean exists = repo.findByUsername(username)
			.map(u -> excludeId == null || !u.getId().equals(excludeId))
			.orElse(false);
		return java.util.Collections.singletonMap("exists", exists);
	}
	
	@GetMapping("/tenants/exists")
	public java.util.Map<String, Object> tenantExists(@RequestParam String tenantName) {
		boolean exists = tenantRepository.existsByTenantName(tenantName.trim());
		return java.util.Collections.singletonMap("exists", exists);
	}

	@PostMapping
	public User create(@RequestBody User user) {
		if (user.getPassword() != null && !user.getPassword().isEmpty()) {
			user.setPassword(encoder.encode(user.getPassword()));
		}
		return repo.save(user);
	}

	@PutMapping("/{id}")
	public ResponseEntity<User> update(@PathVariable Long id, @RequestBody User user) {
		return repo.findById(id).map(existing -> {
			existing.setUsername(user.getUsername());
			existing.setEmail(user.getEmail());
			existing.setFirstName(user.getFirstName());
			existing.setLastName(user.getLastName());
			existing.setRole(user.getRole());
			existing.setEnabled(user.isEnabled());
			if (user.getPassword() != null && !user.getPassword().isEmpty()) {
				existing.setPassword(encoder.encode(user.getPassword()));
			}
			return ResponseEntity.ok(repo.save(existing));
		}).orElse(ResponseEntity.notFound().build());
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<Void> delete(@PathVariable Long id) {
		if (!repo.existsById(id)) return ResponseEntity.notFound().build();
		repo.deleteById(id);
		return ResponseEntity.noContent().build();
	}
}


