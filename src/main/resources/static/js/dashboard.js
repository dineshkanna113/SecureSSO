async function loadSSOConfig() {
	const res = await fetch('/api/sso/config');
	return await res.json();
}

async function toggleSSO() {
	const cfg = await loadSSOConfig();
	const res = await fetch(`/api/sso/toggle?enabled=${!cfg.ssoEnabled}`, { method: 'POST' });
	if (res.ok) location.reload();
}

function openModal(id) { document.getElementById(id).style.display='flex'; }
function closeModal(id) { document.getElementById(id).style.display='none'; }

async function saveOIDC() {
	const body = {
		ssoEnabled: true,
		activeProtocol: 'OIDC',
		oidcClientId: document.getElementById('oidcClientId').value,
		oidcClientSecret: document.getElementById('oidcClientSecret').value,
		oidcRedirectUri: document.getElementById('oidcRedirectUri').value,
		oidcIssuerUri: document.getElementById('oidcIssuerUri').value,
		oidcScopes: document.getElementById('oidcScopes').value
	};
	const res = await fetch('/api/sso/config', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
	if (res.ok) closeModal('oidcModal');
}

async function saveSAML() {
	const body = {
		ssoEnabled: true,
		activeProtocol: 'SAML',
		samlEntityId: document.getElementById('samlEntityId').value,
		samlSsoUrl: document.getElementById('samlSsoUrl').value,
		samlX509Cert: document.getElementById('samlX509Cert').value,
		samlMetadataXml: document.getElementById('samlMetadataXml').value
	};
	const res = await fetch('/api/sso/config', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
	if (res.ok) closeModal('samlModal');
}

async function saveNewSSO() {
	const type = document.getElementById('newProviderType').value;
	const name = document.getElementById('newProviderName').value;
	if (type === 'OIDC') {
		const body = {
			ssoEnabled: true,
			activeProtocol: 'OIDC',
			oidcClientId: document.getElementById('newOidcClientId').value,
			oidcClientSecret: document.getElementById('newOidcClientSecret').value,
			oidcIssuerUri: document.getElementById('newOidcIssuerUri').value,
			oidcRedirectUri: document.getElementById('newOidcRedirectUri').value,
			oidcScopes: document.getElementById('newOidcScopes').value
		};
		await fetch('/api/sso/config', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
	} else {
		const body = {
			ssoEnabled: true,
			activeProtocol: 'SAML',
			samlEntityId: document.getElementById('newSamlEntityId').value,
			samlSsoUrl: document.getElementById('newSamlSsoUrl').value,
			samlX509Cert: document.getElementById('newSamlX509Cert').value,
			samlMetadataXml: document.getElementById('samlMetadataXml') ? document.getElementById('samlMetadataXml').value : ''
		};
		await fetch('/api/sso/config', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
	}
	closeModal('addSsoModal');
	location.reload();
}

window.nf = { toggleSSO, openModal, closeModal, saveOIDC, saveSAML, saveNewSSO };


