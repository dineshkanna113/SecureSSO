package com.example.finalsso.controller.api;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.service.SSOConfigService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sso")
public class SSOConfigController {

	private final SSOConfigService service;

	public SSOConfigController(SSOConfigService service) {
		this.service = service;
	}

	@GetMapping("/config")
	public SSOConfig get() { return service.get(); }

	@PutMapping("/config")
	public SSOConfig save(@RequestBody SSOConfig cfg) { return service.save(cfg); }

	@PostMapping("/toggle")
	public SSOConfig toggle(@RequestParam boolean enabled) { return service.toggle(enabled); }

	@PostMapping("/protocol")
	public SSOConfig protocol(@RequestParam String protocol) { return service.setProtocol(protocol); }
}


