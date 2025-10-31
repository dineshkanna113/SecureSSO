package com.example.finalsso.controller;

import com.example.finalsso.entity.User;
import com.example.finalsso.service.SSOConfigService;
import com.example.finalsso.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private SSOConfigService ssoConfigService;

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user) {
        userService.register(user);
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(value = "native", required = false) String nativeLogin, Model model) {
        model.addAttribute("config", ssoConfigService.get());
        model.addAttribute("forceNative", nativeLogin != null);
        return "login";
    }

    @GetMapping("/login/sso")
    public String loginSso(Model model) {
        model.addAttribute("config", ssoConfigService.get());
        return "login_sso";
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access_denied";
    }
}
