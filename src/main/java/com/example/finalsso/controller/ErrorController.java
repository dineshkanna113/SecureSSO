package com.example.finalsso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ErrorController {
    
    @GetMapping("/error")
    public String error(@RequestParam(required = false) String message, Model model) {
        model.addAttribute("message", message != null ? message : "An error occurred");
        return "error";
    }
}

