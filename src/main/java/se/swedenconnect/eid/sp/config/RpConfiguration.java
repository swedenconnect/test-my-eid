/*
 * Copyright 2018-2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.eid.sp.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import se.swedenconnect.eid.sp.oidc.LoaTrustMarkChecker;
import se.swedenconnect.eid.sp.oidc.OidcRequestFactory;
import se.swedenconnect.eid.sp.oidc.OidcResponseProcessor;
import se.swedenconnect.eid.sp.oidc.OpRegistry;
import se.swedenconnect.eid.sp.oidc.RelyingParty;
import se.swedenconnect.eid.sp.oidc.RelyingPartyFactory;
import se.swedenconnect.eid.sp.oidc.federation.EntityConfigurationService;
import se.swedenconnect.eid.sp.oidc.federation.FederationClient;
import se.swedenconnect.eid.sp.oidc.federation.FederationOpSource;
import se.swedenconnect.eid.sp.oidc.federation.FederationService;
import se.swedenconnect.eid.sp.oidc.federation.RpTrustMarkService;
import se.swedenconnect.eid.sp.oidc.federation.TrustAnchorResolver;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Configuration for the OpenID Connect Relying Party.
 *
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties({ RpConfigurationProperties.class })
public class RpConfiguration {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(RpConfiguration.class);

  /** The OIDC RP settings. */
  private final RpConfigurationProperties properties;

  /** The SAML SP settings. */
  private final SpConfigurationProperties spProperties;

  /**
   * Constructor.
   *
   * @param properties the OIDC RP settings
   * @param spProperties the SAML SP settings
   */
  public RpConfiguration(final @NonNull RpConfigurationProperties properties,
      final @NonNull SpConfigurationProperties spProperties) {
    this.properties = properties;
    this.spProperties = spProperties;
  }

  /**
   * Gets the clock used by the OIDC components.
   *
   * @return a {@link Clock}
   */
  @Bean("oidcClock")
  @NonNull Clock oidcClock() {
    return Clock.systemUTC();
  }

  /**
   * Creates the Relying Party.
   *
   * @param contextPath the servlet context path
   * @param credentialFactory the credential factory
   * @return the {@link RelyingParty}
   */
  @Bean
  @NonNull RelyingParty relyingParty(@Value("${server.servlet.context-path:/}") final @NonNull String contextPath,
      final @NonNull PkiCredentialFactory credentialFactory) {
    return RelyingPartyFactory.create(this.spProperties, this.properties, contextPath, c -> {
      try {
        final PkiCredential credential = credentialFactory.createCredential(c);
        if (credential == null) {
          throw new IllegalStateException("Failed to load credential");
        }
        return credential;
      }
      catch (final Exception e) {
        throw new IllegalStateException("Failed to load OIDC credential - " + e.getMessage(), e);
      }
    });
  }

  /**
   * Creates the service that signs and caches the entity configuration.
   *
   * @param relyingParty the Relying Party
   * @param clock the clock
   * @return the {@link EntityConfigurationService}
   */
  @Bean
  @NonNull EntityConfigurationService entityConfigurationService(final @NonNull RelyingParty relyingParty,
      final @NonNull Clock clock) {
    return new EntityConfigurationService(relyingParty, this.properties.getEntityConfigurationLifetime(), clock);
  }

  /**
   * Creates the factory for OIDC authentication requests.
   *
   * @param relyingParty the Relying Party
   * @param userMessages the Markdown user message templates
   * @param clock the clock
   * @return the {@link OidcRequestFactory}
   * @throws IOException if the plain-text templates can not be read
   */
  @Bean
  @NonNull OidcRequestFactory oidcRequestFactory(final @NonNull RelyingParty relyingParty,
      @Qualifier("userMessages") final @NonNull Map<String, String> userMessages,
      final @NonNull Clock clock) throws IOException {
    final Map<String, String> plain = new LinkedHashMap<>();
    for (final Map.Entry<String, Resource> e : this.properties.getPlainUserMessageTemplate().entrySet()) {
      try (final InputStream is = e.getValue().getInputStream()) {
        plain.put(e.getKey(), new String(is.readAllBytes(), StandardCharsets.UTF_8).trim());
      }
    }
    return new OidcRequestFactory(relyingParty, userMessages, plain, clock);
  }

  /**
   * Creates the processor for OIDC responses.
   *
   * @param relyingParty the Relying Party
   * @param clock the clock
   * @return the {@link OidcResponseProcessor}
   */
  @Bean
  @NonNull OidcResponseProcessor oidcResponseProcessor(final @NonNull RelyingParty relyingParty,
      final @NonNull Clock clock) {
    return new OidcResponseProcessor(relyingParty, clock);
  }

  /**
   * Creates the checker for the OP's Level of Assurance trust marks.
   *
   * @return the {@link LoaTrustMarkChecker}
   */
  @Bean
  @NonNull LoaTrustMarkChecker loaTrustMarkChecker() {
    return new LoaTrustMarkChecker(this.properties.getFederation().getLoaTrustMarks());
  }

  /**
   * Creates the OpenID Federation service, and connects it to the OP registry (OPs found through the federation)
   * and the entity configuration (authority hints and trust marks). Only created when federation is enabled.
   *
   * @param relyingParty the Relying Party
   * @param opRegistry the OP registry
   * @param entityConfigurationService the entity configuration service
   * @param clock the clock
   * @return the {@link FederationService}
   */
  @Bean(initMethod = "start", destroyMethod = "stop")
  @ConditionalOnProperty(name = "rp.federation.enabled", havingValue = "true")
  @NonNull FederationService federationService(final @NonNull RelyingParty relyingParty,
      final @NonNull OpRegistry opRegistry, final @NonNull EntityConfigurationService entityConfigurationService,
      final @NonNull Clock clock) {

    final RpConfigurationProperties.Federation federation = this.properties.getFederation();
    final FederationClient client = new FederationClient();
    final TrustAnchorResolver resolver = new TrustAnchorResolver(
        Objects.requireNonNull(federation.getTrustAnchor().getEntityId()), trustAnchorKeys(federation.getTrustAnchor()),
        Optional.ofNullable(federation.getTrustAnchor().getResolveEndpoint()).map(URI::create).orElse(null),
        client, clock);
    final FederationOpSource opSource = new FederationOpSource(resolver, client,
        federation.getEffectiveListingSources(), federation.getRefreshInterval(), federation.getRetryInterval(), clock);
    final RpTrustMarkService trustMarkService = new RpTrustMarkService(relyingParty.getEntityId(),
        federation.getTrustMarkIssuers(), resolver, client, federation.getRefreshInterval(),
        federation.getRetryInterval(), clock);

    opRegistry.setFederationProviders(opSource::getProviders);
    final List<String> authorityHints = List.copyOf(federation.getAuthorityHints());
    if (authorityHints.isEmpty()) {
      log.warn("OpenID Federation is enabled but no authority hints are configured (rp.federation.authority-hints)");
    }
    entityConfigurationService.setAuthorityHintsSupplier(() -> authorityHints);
    entityConfigurationService.setTrustMarksSupplier(trustMarkService::getTrustMarks);

    return new FederationService(opSource, trustMarkService, federation.getRetryInterval());
  }

  /**
   * Reads the trust anchor's federation keys from the configuration.
   *
   * @param trustAnchor the trust anchor settings
   * @return the keys
   */
  private static @NonNull JWKSet trustAnchorKeys(final RpConfigurationProperties.@NonNull TrustAnchor trustAnchor) {
    try {
      final String json;
      if (StringUtils.hasText(trustAnchor.getJwks())) {
        json = trustAnchor.getJwks();
      }
      else {
        try (final InputStream is = Objects.requireNonNull(trustAnchor.getJwksResource()).getInputStream()) {
          json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
      }
      final Map<String, Object> parsed = JSONObjectUtils.parse(json);
      final JWKSet keys = parsed.containsKey("keys") ? JWKSet.parse(parsed) : new JWKSet(JWK.parse(parsed));
      if (keys.getKeys().isEmpty()) {
        throw new IllegalStateException("No keys given for the trust anchor");
      }
      return keys.toPublicJWKSet();
    }
    catch (final IOException | java.text.ParseException e) {
      throw new IllegalStateException("Invalid trust anchor key (rp.federation.trust-anchor.jwks or jwks-resource) - "
          + e.getMessage(), e);
    }
  }

  /**
   * Creates the registry of OpenID Providers.
   *
   * @param clock the clock
   * @return the {@link OpRegistry}
   */
  @Bean(initMethod = "start", destroyMethod = "stop")
  @NonNull OpRegistry opRegistry(final @NonNull Clock clock) {
    return new OpRegistry(this.properties.getProviders(), this.properties.getDiscovery(), clock);
  }

}
