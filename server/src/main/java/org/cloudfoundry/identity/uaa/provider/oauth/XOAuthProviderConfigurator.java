package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;

public class XOAuthProviderConfigurator implements IdentityProviderProvisioning {

    private static Logger LOGGER = LoggerFactory.getLogger(XOAuthProviderConfigurator.class);

    private final IdentityProviderProvisioning providerProvisioning;
    private final OidcMetadataFetcher oidcMetadataFetcher;
    private final UaaRandomStringUtil uaaRandomStringUtil;

    public XOAuthProviderConfigurator(
            final IdentityProviderProvisioning providerProvisioning,
            final OidcMetadataFetcher oidcMetadataFetcher,
            final UaaRandomStringUtil uaaRandomStringUtil) {
        this.providerProvisioning = providerProvisioning;
        this.oidcMetadataFetcher = oidcMetadataFetcher;
        this.uaaRandomStringUtil = uaaRandomStringUtil;
    }

    protected OIDCIdentityProviderDefinition overlay(OIDCIdentityProviderDefinition definition) {
        try {
            oidcMetadataFetcher.fetchMetadataAndUpdateDefinition(definition);
            return definition;
        } catch (OidcMetadataFetchingException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getCompleteAuthorizationURI(
            final String alias,
            final String baseURL,
            final AbstractXOAuthIdentityProviderDefinition definition) {
        String authUrlBase;
        if (definition instanceof OIDCIdentityProviderDefinition) {
            authUrlBase = overlay((OIDCIdentityProviderDefinition) definition).getAuthUrl().toString();
        } else {
            authUrlBase = definition.getAuthUrl().toString();
        }
        String queryAppendDelimiter = authUrlBase.contains("?") ? "&" : "?";
        List<String> query = new ArrayList<>();
        query.add("client_id=" + definition.getRelyingPartyId());
        query.add("response_type=" + URLEncoder.encode(definition.getResponseType(), StandardCharsets.UTF_8));
        query.add("redirect_uri=" + URLEncoder.encode(baseURL + "/login/callback/" + alias, StandardCharsets.UTF_8));
        query.add("state=" + uaaRandomStringUtil.getSecureRandom(10));
        if (definition.getScopes() != null && !definition.getScopes().isEmpty()) {
            query.add("scope=" + URLEncoder.encode(String.join(" ", definition.getScopes()), StandardCharsets.UTF_8));
        }
        if (OIDCIdentityProviderDefinition.class.equals(definition.getParameterizedClass())) {
            final RandomValueStringGenerator nonceGenerator = new RandomValueStringGenerator(12);
            query.add("nonce=" + nonceGenerator.generate());
        }
        String queryString = String.join("&", query);
        return authUrlBase + queryAppendDelimiter + queryString;
    }

    @Override
    public IdentityProvider create(IdentityProvider identityProvider, String zoneId) {
        return providerProvisioning.create(identityProvider, zoneId);
    }

    @Override
    public IdentityProvider update(IdentityProvider identityProvider, String zoneId) {
        return providerProvisioning.update(identityProvider, zoneId);
    }

    @Override
    public IdentityProvider retrieve(String id, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieve(id, zoneId);
        if (p != null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }

    @Override
    public List<IdentityProvider> retrieveActive(String zoneId) {
        return retrieveAll(true, zoneId);
    }

    public IdentityProvider retrieveByIssuer(String issuer, String zoneId) throws IncorrectResultSizeDataAccessException {
        List<IdentityProvider> providers = retrieveAll(true, zoneId)
                .stream()
                .filter(p -> OIDC10.equals(p.getType()) &&
                        issuer.equals(((OIDCIdentityProviderDefinition) p.getConfig()).getIssuer()))
                .collect(Collectors.toList());
        if (providers.isEmpty()) {
            throw new IncorrectResultSizeDataAccessException(String.format("Active provider with issuer[%s] not found", issuer), 1);
        } else if (providers.size() > 1) {
            throw new IncorrectResultSizeDataAccessException(String.format("Duplicate providers with issuer[%s] not found", issuer), 1);
        }
        return providers.get(0);
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        final List<String> types = Arrays.asList(OAUTH20, OIDC10);
        List<IdentityProvider> providers = providerProvisioning.retrieveAll(activeOnly, zoneId);
        List<IdentityProvider> overlayedProviders = new ArrayList<>();
        ofNullable(providers).orElse(emptyList()).stream()
                .filter(p -> types.contains(p.getType()))
                .forEach(p -> {
                    if (p.getType().equals(OIDC10)) {
                        try {
                            OIDCIdentityProviderDefinition overlayedDefinition = overlay((OIDCIdentityProviderDefinition) p.getConfig());
                            p.setConfig(overlayedDefinition);
                        } catch (Exception e) {
                            LOGGER.error("Identity provider excluded from login page due to a problem.", e);
                            return;
                        }
                    }
                    overlayedProviders.add(p);
                });
        return overlayedProviders;
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieveByOrigin(origin, zoneId);
        if (p != null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }

    @Override
    public IdentityProvider retrieveByOriginIgnoreActiveFlag(String origin, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieveByOriginIgnoreActiveFlag(origin, zoneId);
        if (p != null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }
}
