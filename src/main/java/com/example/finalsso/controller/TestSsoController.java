package com.example.finalsso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
public class TestSsoController {

    @GetMapping("/test/sso/saml")
    public String testSaml(@RequestParam(required = false) Long providerId, HttpServletRequest request) {
        var session = request.getSession(true);
        session.setAttribute("saml_test", true);
        if (providerId != null) {
            session.setAttribute("saml_test_provider_id", providerId);
        }
        return "redirect:/sso/saml2/authenticate";
    }

    @GetMapping("/test/sso/oidc")
    public String testOidc(@RequestParam(required = false) Long providerId, HttpServletRequest request) {
        var session = request.getSession(true);
        session.setAttribute("oidc_test", true);
        if (providerId != null) {
            session.setAttribute("oidc_test_provider_id", providerId);
        }
        return "redirect:/sso/oauth2/authorize" + (providerId != null ? "?providerId=" + providerId : "");
    }

    @GetMapping("/test/sso/jwt")
    public String testJwt(@RequestParam(required = false) Long providerId, HttpServletRequest request) {
        var session = request.getSession(true);
        session.setAttribute("jwt_test", true);
        if (providerId != null) {
            session.setAttribute("jwt_test_provider_id", providerId);
        }
        return "redirect:/sso/jwt/authenticate" + (providerId != null ? "?providerId=" + providerId : "");
    }

    @GetMapping("/test/jwt/result")
    public String jwtResult(Model model, HttpServletRequest request) {
        var session = request.getSession(false);
        if (session == null) {
            return "redirect:/admin/dashboard";
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) session.getAttribute("jwt_test_result");
        if (claims == null) {
            return "redirect:/admin/dashboard";
        }
        session.removeAttribute("jwt_test_result");
        model.addAttribute("claims", claims);
        model.addAttribute("protocol", "JWT");
        return "test_sso_result";
    }
}




