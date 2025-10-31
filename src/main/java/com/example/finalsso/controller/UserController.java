package com.example.finalsso.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/user")
public class UserController {

	@GetMapping("/dashboard")
	public String dashboard(Authentication authentication, Model model) {
		model.addAttribute("username", authentication != null ? authentication.getName() : "User");
		String method = "LOCAL";
		if (authentication != null && authentication.getPrincipal() instanceof OidcUser) method = "OIDC";
		if (authentication != null && authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal) method = "SAML";
		model.addAttribute("method", method);
		return "user/dashboard";
	}
}


