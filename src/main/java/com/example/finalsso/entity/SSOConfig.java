package com.example.finalsso.entity;

import javax.persistence.*;

@Entity
@Table(name = "sso_config")
public class SSOConfig {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private boolean ssoEnabled = true;

	@Column(nullable = false)
	private String activeProtocol = "OIDC"; // OIDC, SAML, DEFAULT

	// OIDC fields
	private String oidcClientId;
	private String oidcClientSecret;
	private String oidcRedirectUri;
	private String oidcIssuerUri;
	private String oidcScopes; // comma-separated
	private String oidcAuthorizationEndpoint;
	private String oidcTokenEndpoint;
	private String oidcUserInfoEndpoint;
	private String oidcLogoutEndpoint;

	// SAML fields
	private String samlEntityId;
	private String samlSsoUrl;
	@Column(length = 8192)
	private String samlX509Cert;
	@Column(length = 16384)
	private String samlMetadataXml;

	public Long getId() { return id; }
	public void setId(Long id) { this.id = id; }
	public boolean isSsoEnabled() { return ssoEnabled; }
	public void setSsoEnabled(boolean ssoEnabled) { this.ssoEnabled = ssoEnabled; }
	public String getActiveProtocol() { return activeProtocol; }
	public void setActiveProtocol(String activeProtocol) { this.activeProtocol = activeProtocol; }
	public String getOidcClientId() { return oidcClientId; }
	public void setOidcClientId(String oidcClientId) { this.oidcClientId = oidcClientId; }
	public String getOidcClientSecret() { return oidcClientSecret; }
	public void setOidcClientSecret(String oidcClientSecret) { this.oidcClientSecret = oidcClientSecret; }
	public String getOidcRedirectUri() { return oidcRedirectUri; }
	public void setOidcRedirectUri(String oidcRedirectUri) { this.oidcRedirectUri = oidcRedirectUri; }
	public String getOidcIssuerUri() { return oidcIssuerUri; }
	public void setOidcIssuerUri(String oidcIssuerUri) { this.oidcIssuerUri = oidcIssuerUri; }
	public String getOidcScopes() { return oidcScopes; }
	public void setOidcScopes(String oidcScopes) { this.oidcScopes = oidcScopes; }
	public String getOidcAuthorizationEndpoint() { return oidcAuthorizationEndpoint; }
	public void setOidcAuthorizationEndpoint(String oidcAuthorizationEndpoint) { this.oidcAuthorizationEndpoint = oidcAuthorizationEndpoint; }
	public String getOidcTokenEndpoint() { return oidcTokenEndpoint; }
	public void setOidcTokenEndpoint(String oidcTokenEndpoint) { this.oidcTokenEndpoint = oidcTokenEndpoint; }
	public String getOidcUserInfoEndpoint() { return oidcUserInfoEndpoint; }
	public void setOidcUserInfoEndpoint(String oidcUserInfoEndpoint) { this.oidcUserInfoEndpoint = oidcUserInfoEndpoint; }
	public String getOidcLogoutEndpoint() { return oidcLogoutEndpoint; }
	public void setOidcLogoutEndpoint(String oidcLogoutEndpoint) { this.oidcLogoutEndpoint = oidcLogoutEndpoint; }
	public String getSamlEntityId() { return samlEntityId; }
	public void setSamlEntityId(String samlEntityId) { this.samlEntityId = samlEntityId; }
	public String getSamlSsoUrl() { return samlSsoUrl; }
	public void setSamlSsoUrl(String samlSsoUrl) { this.samlSsoUrl = samlSsoUrl; }
	public String getSamlX509Cert() { return samlX509Cert; }
	public void setSamlX509Cert(String samlX509Cert) { this.samlX509Cert = samlX509Cert; }
	public String getSamlMetadataXml() { return samlMetadataXml; }
	public void setSamlMetadataXml(String samlMetadataXml) { this.samlMetadataXml = samlMetadataXml; }
}


