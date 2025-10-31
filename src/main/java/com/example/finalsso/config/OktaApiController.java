package com.example.finalsso.config;

import com.example.finalsso.service.OktaApiService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OktaApiController {

    private final OktaApiService oktaApiService;

    public OktaApiController(OktaApiService oktaApiService) {
        this.oktaApiService = oktaApiService;
    }

    @GetMapping("/okta/users")
    public String getUsers() {
        return oktaApiService.listUsers();
    }
}
