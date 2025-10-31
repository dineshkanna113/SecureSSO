package com.example.finalsso.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/hello")
    public String helloPage(@AuthenticationPrincipal Object principal, Model model) {
        if (principal instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) principal;
            model.addAttribute("name", oidcUser.getFullName());
            model.addAttribute("email", oidcUser.getEmail());
        } else if (principal instanceof Saml2AuthenticatedPrincipal samlUser) {
            model.addAttribute("name", samlUser.getName());
            model.addAttribute("email", samlUser.getFirstAttribute("email"));
            model.addAttribute("method", "SAML 2.0 (Okta)");
        } else {
            model.addAttribute("name", "Local User");
            model.addAttribute("email", "N/A");
        }
        return "hello";
    }
}
