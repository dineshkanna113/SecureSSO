package com.example.finalsso.service;

import com.example.finalsso.entity.SSOConfig;
import com.example.finalsso.entity.Tenant;
import com.example.finalsso.repository.SSOConfigRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class SSOConfigService {

	private final SSOConfigRepository repository;

	public SSOConfigService(SSOConfigRepository repository) {
		this.repository = repository;
	}

	/**
	 * Get global SSO config (for super admin)
	 */
	public SSOConfig get() {
		return repository.findByTenantIsNull()
			.orElseGet(() -> {
				SSOConfig config = new SSOConfig();
				config.setTenant(null);
				return repository.save(config);
			});
	}

	/**
	 * Get tenant-specific SSO config
	 */
	public SSOConfig getByTenant(Tenant tenant) {
		if (tenant == null) {
			return get();
		}
		return repository.findByTenant(tenant)
			.orElseGet(() -> {
				SSOConfig config = new SSOConfig();
				config.setTenant(tenant);
				config.setSsoEnabled(false);
				return repository.save(config);
			});
	}

	/**
	 * Save tenant-specific SSO config
	 */
	@Transactional
	public SSOConfig saveForTenant(SSOConfig incoming, Tenant tenant) {
		if (tenant == null) {
			return save(incoming);
		}
		
		SSOConfig current = getByTenant(tenant);
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
		current.setJwtIssuer(incoming.getJwtIssuer());
		current.setJwtAudience(incoming.getJwtAudience());
		current.setJwtJwksUri(incoming.getJwtJwksUri());
		current.setJwtHeaderName(incoming.getJwtHeaderName());
		current.setJwtCertificate(incoming.getJwtCertificate());
		current.setJwtSsoUrl(incoming.getJwtSsoUrl());
		current.setJwtClientId(incoming.getJwtClientId());
		current.setJwtClientSecret(incoming.getJwtClientSecret());
		current.setJwtRedirectUri(incoming.getJwtRedirectUri());
		current.setProviderName(incoming.getProviderName());
		current.setTenant(tenant);
		return repository.save(current);
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
		current.setJwtIssuer(incoming.getJwtIssuer());
		current.setJwtAudience(incoming.getJwtAudience());
		current.setJwtJwksUri(incoming.getJwtJwksUri());
		current.setJwtHeaderName(incoming.getJwtHeaderName());
		current.setJwtCertificate(incoming.getJwtCertificate());
		current.setJwtSsoUrl(incoming.getJwtSsoUrl());
		current.setJwtClientId(incoming.getJwtClientId());
		current.setJwtClientSecret(incoming.getJwtClientSecret());
		current.setJwtRedirectUri(incoming.getJwtRedirectUri());
		current.setProviderName(incoming.getProviderName());
		return repository.save(current);
	}

	@Transactional
	public SSOConfig toggle(boolean enabled) {
		SSOConfig current = get();
		current.setSsoEnabled(enabled);
		return repository.save(current);
	}

	@Transactional
	public SSOConfig toggleForTenant(boolean enabled, Tenant tenant) {
		if (tenant == null) {
			return toggle(enabled);
		}
		SSOConfig current = getByTenant(tenant);
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


