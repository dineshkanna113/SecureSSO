package com.example.finalsso.controller;

import com.example.finalsso.service.UserCompanyMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/{company}/enduser")
public class CompanyEndUserController {

    private final UserCompanyMapper userCompanyMapper;

    public CompanyEndUserController(UserCompanyMapper userCompanyMapper) {
        this.userCompanyMapper = userCompanyMapper;
    }

    @GetMapping("/dashboard")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public String dashboard(@PathVariable String company, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        
        if (username == null) {
            return "redirect:/login?error=not_authenticated";
        }
        
        // Validate company context - this will handle tenant initialization
        if (!userCompanyMapper.validateCompanyContext(username, company)) {
            return "redirect:/login?error=access_denied";
        }
        
        model.addAttribute("username", username);
        model.addAttribute("company", company);
        
        return "company-enduser/dashboard";
    }
}

