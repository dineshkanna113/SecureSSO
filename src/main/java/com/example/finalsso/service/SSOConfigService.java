package com.example.finalsso.service;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.repository.SSOConfigRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SSOConfigService {

	private final SSOConfigRepository repository;

	public SSOConfigService(SSOConfigRepository repository) {
		this.repository = repository;
	}

	public SSOConfig get() {
		return repository.findAll().stream().findFirst().orElseGet(() -> repository.save(new SSOConfig()));
	}

	@Transactional
	public SSOConfig save(SSOConfig incoming) {
		SSOConfig current = get();
		current.setSsoEnabled(incoming.isSsoEnabled());
		current.setActiveProtocol(incoming.getActiveProtocol());
		current.setOidcClientId(incoming.getOidcClientId());
		current.setOidcClientSecret(incoming.getOidcClientSecret());
		current.setOidcRedirectUri(incoming.getOidcRedirectUri());
		current.setOidcIssuerUri(incoming.getOidcIssuerUri());
		current.setOidcScopes(incoming.getOidcScopes());
		current.setOidcAuthorizationEndpoint(incoming.getOidcAuthorizationEndpoint());
		current.setOidcTokenEndpoint(incoming.getOidcTokenEndpoint());
		current.setOidcUserInfoEndpoint(incoming.getOidcUserInfoEndpoint());
		current.setOidcLogoutEndpoint(incoming.getOidcLogoutEndpoint());
		current.setSamlEntityId(incoming.getSamlEntityId());
		current.setSamlSsoUrl(incoming.getSamlSsoUrl());
		current.setSamlX509Cert(incoming.getSamlX509Cert());
		current.setSamlMetadataXml(incoming.getSamlMetadataXml());
		return repository.save(current);
	}

	@Transactional
	public SSOConfig toggle(boolean enabled) {
		SSOConfig current = get();
		current.setSsoEnabled(enabled);
		return repository.save(current);
	}

	@Transactional
	public SSOConfig setProtocol(String protocol) {
		SSOConfig current = get();
		current.setActiveProtocol(protocol);
		return repository.save(current);
	}
}


