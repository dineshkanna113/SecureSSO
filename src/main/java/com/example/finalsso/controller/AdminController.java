package com.example.finalsso.controller;

import com.example.finalsso.entity.User;
import com.example.finalsso.repository.UserRepository;
import com.example.finalsso.service.SSOConfigService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/admin")
public class AdminController {

	private final UserRepository userRepository;
	private final SSOConfigService ssoConfigService;
	private final PasswordEncoder passwordEncoder;

	public AdminController(UserRepository userRepository, SSOConfigService ssoConfigService, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.ssoConfigService = ssoConfigService;
		this.passwordEncoder = passwordEncoder;
	}

	@GetMapping("/dashboard")
	public String dashboard(Model model) {
		model.addAttribute("users", userRepository.findAll());
		model.addAttribute("config", ssoConfigService.get());
		return "admin/dashboard";
	}

	@GetMapping("/users/new")
	public String newUser(Model model) {
		model.addAttribute("user", new User());
		return "admin/user_form";
	}

	@PostMapping("/users")
    public String createUser(@ModelAttribute User user, org.springframework.ui.Model model) {
        java.util.Optional<com.example.finalsso.entity.User> existingByUsername = userRepository.findByUsername(user.getUsername());
        if (existingByUsername.isPresent()) {
            model.addAttribute("user", user);
            model.addAttribute("error", "Username already exists");
            return "admin/user_form";
        }
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        userRepository.save(user);
        return "redirect:/admin/dashboard";
    }

	@GetMapping("/users/{id}/edit")
	public String editUser(@PathVariable Long id, Model model) {
		User user = userRepository.findById(id).orElseThrow();
		model.addAttribute("user", user);
		return "admin/user_form";
	}

	@PostMapping("/users/{id}")
    public String updateUser(@PathVariable Long id, @ModelAttribute User user, org.springframework.ui.Model model) {
        User existing = userRepository.findById(id).orElseThrow();
        java.util.Optional<com.example.finalsso.entity.User> clash = userRepository.findByUsername(user.getUsername());
        if (clash.isPresent() && !clash.get().getId().equals(id)) {
            user.setId(id);
            model.addAttribute("user", user);
            model.addAttribute("error", "Username already exists");
            return "admin/user_form";
        }
        existing.setUsername(user.getUsername());
        existing.setEmail(user.getEmail());
        existing.setFirstName(user.getFirstName());
        existing.setLastName(user.getLastName());
        existing.setRole(user.getRole());
        existing.setEnabled(user.isEnabled());
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            existing.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        userRepository.save(existing);
        return "redirect:/admin/dashboard";
    }

	@PostMapping("/users/{id}/delete")
	public String deleteUser(@PathVariable Long id, org.springframework.web.servlet.mvc.support.RedirectAttributes ra) {
		User u = userRepository.findById(id).orElse(null);
		if (u != null && "ROLE_ADMIN".equals(u.getRole())) {
			long admins = userRepository.countByRole("ROLE_ADMIN");
			if (admins <= 1) {
				ra.addFlashAttribute("error", "Cannot delete the last administrator.");
				return "redirect:/admin/dashboard";
			}
		}
		userRepository.deleteById(id);
		return "redirect:/admin/dashboard";
	}
}


