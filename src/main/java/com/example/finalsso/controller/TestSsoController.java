package com.example.finalsso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;

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
}




