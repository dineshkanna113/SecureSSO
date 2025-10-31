package com.example.finalsso.entity;

import javax.persistence.*;

@Entity
@Table(name = "sso_provider")
public class SSOProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name; // Provider label

    @Column(nullable = false)
    private String type; // OIDC, SAML, or JWT

    // OIDC fields
    private String oidcClientId;
    private String oidcClientSecret;
    private String oidcRedirectUri;
    private String oidcIssuerUri;
    private String oidcScopes;
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
    private String samlMetadataUrl;

    // JWT fields
    private String jwtIssuer;
    private String jwtAudience;
    private String jwtJwksUri;
    private String jwtHeaderName;
    @Column(length = 8192)
    private String jwtCertificate; // PEM-encoded public key/cert for signature validation

    private Boolean active = false;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

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
    public String getSamlMetadataUrl() { return samlMetadataUrl; }
    public void setSamlMetadataUrl(String samlMetadataUrl) { this.samlMetadataUrl = samlMetadataUrl; }

    public String getJwtIssuer() { return jwtIssuer; }
    public void setJwtIssuer(String jwtIssuer) { this.jwtIssuer = jwtIssuer; }
    public String getJwtAudience() { return jwtAudience; }
    public void setJwtAudience(String jwtAudience) { this.jwtAudience = jwtAudience; }
    public String getJwtJwksUri() { return jwtJwksUri; }
    public void setJwtJwksUri(String jwtJwksUri) { this.jwtJwksUri = jwtJwksUri; }
    public String getJwtHeaderName() { return jwtHeaderName; }
    public void setJwtHeaderName(String jwtHeaderName) { this.jwtHeaderName = jwtHeaderName; }
    public String getJwtCertificate() { return jwtCertificate; }
    public void setJwtCertificate(String jwtCertificate) { this.jwtCertificate = jwtCertificate; }

    public boolean isActive() { return Boolean.TRUE.equals(active); }
    public void setActive(boolean active) { this.active = active; }
}


