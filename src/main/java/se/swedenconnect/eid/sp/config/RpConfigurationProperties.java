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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.CredentialsConfiguration.PkiCredentialConfiguration;
import se.swedenconnect.opensaml.common.utils.LocalizedString;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration properties for the OpenID Connect Relying Party.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("rp")
public class RpConfigurationProperties implements InitializingBean {

  /**
   * The RP's entity identifier, also used as its client ID towards every OP. Defaults to the base URI plus the servlet
   * context path.
   */
  private @Nullable String entityId;

  /**
   * Gets the RP's entity identifier, also used as its client ID towards every OP.
   *
   * @return the entity ID
   */
  public @Nullable String getEntityId() {
    return this.entityId;
  }

  /**
   * Assigns the RP's entity identifier, also used as its client ID towards every OP.
   *
   * @param entityId the entity ID
   */
  public void setEntityId(final @Nullable String entityId) {
    this.entityId = entityId;
  }

  /**
   * The RP credentials.
   */
  @NestedConfigurationProperty
  private @NonNull Credentials credential = new Credentials();

  /**
   * Gets the RP credentials.
   *
   * @return the RP credentials
   */
  public @NonNull Credentials getCredential() {
    return this.credential;
  }

  /**
   * The subject type declared in the RP metadata ({@code public} or {@code pairwise}).
   */
  private @NonNull String subjectType = "public";

  /**
   * Gets the subject type declared in the RP metadata ({@code public} or {@code pairwise}).
   *
   * @return the subject type
   */
  public @NonNull String getSubjectType() {
    return this.subjectType;
  }

  /**
   * Assigns the subject type declared in the RP metadata ({@code public} or {@code pairwise}).
   *
   * @param subjectType the subject type
   */
  public void setSubjectType(final @NonNull String subjectType) {
    this.subjectType = subjectType;
  }

  /**
   * Encryption of ID tokens and UserInfo responses.
   */
  @NestedConfigurationProperty
  private @NonNull Encryption encryption = new Encryption();

  /**
   * Gets the encryption of ID tokens and UserInfo responses.
   *
   * @return the encryption of ID tokens and UserInfo responses
   */
  public @NonNull Encryption getEncryption() {
    return this.encryption;
  }

  /**
   * Overrides for the RP metadata values that are otherwise taken from the SAML metadata settings.
   */
  @NestedConfigurationProperty
  private @NonNull Metadata metadata = new Metadata();

  /**
   * Gets the overrides for the RP metadata values that are otherwise taken from the SAML metadata settings.
   *
   * @return the metadata
   */
  public @NonNull Metadata getMetadata() {
    return this.metadata;
  }

  /**
   * The lifetime of the signed entity configuration. It is signed anew when half of the lifetime has passed.
   */
  private @NonNull Duration entityConfigurationLifetime = Duration.ofDays(7);

  /**
   * Gets the lifetime of the signed entity configuration.
   *
   * @return the lifetime of the signed entity configuration
   */
  public @NonNull Duration getEntityConfigurationLifetime() {
    return this.entityConfigurationLifetime;
  }

  /**
   * Assigns the lifetime of the signed entity configuration.
   *
   * @param entityConfigurationLifetime the lifetime of the signed entity configuration
   */
  public void setEntityConfigurationLifetime(final @NonNull Duration entityConfigurationLifetime) {
    this.entityConfigurationLifetime = entityConfigurationLifetime;
  }

  /**
   * OpenID Federation settings.
   */
  @NestedConfigurationProperty
  private @NonNull Federation federation = new Federation();

  /**
   * Gets the OpenID Federation settings.
   *
   * @return the OpenID Federation settings
   */
  public @NonNull Federation getFederation() {
    return this.federation;
  }

  /**
   * Manually configured OpenID Providers.
   */
  private @NonNull List<ProviderConfig> providers = new ArrayList<>();

  /**
   * Gets the manually configured OpenID Providers.
   *
   * @return the manually configured OpenID Providers
   */
  public @NonNull List<ProviderConfig> getProviders() {
    return this.providers;
  }

  /**
   * Assigns the manually configured OpenID Providers.
   *
   * @param providers the manually configured OpenID Providers
   */
  public void setProviders(final @NonNull List<ProviderConfig> providers) {
    this.providers = providers;
  }

  /**
   * Settings for how OPs are listed and refreshed.
   */
  @NestedConfigurationProperty
  private @NonNull Discovery discovery = new Discovery();

  /**
   * Gets the settings for how OPs are listed and refreshed.
   *
   * @return the settings for how OPs are listed and refreshed
   */
  public @NonNull Discovery getDiscovery() {
    return this.discovery;
  }

  /**
   * Terms that, when found in the {@code error_description} of an {@code access_denied} error response
   * (case-insensitive), mean that the user cancelled. The user is then returned to the start page.
   */
  private @NonNull List<String> cancelTerms = new ArrayList<>(List.of(
      "cancel", "cancelled", "canceled", "abort", "aborted",
      "avbryt", "avbruten", "avbrutet", "avbröt", "avbrutit"));

  /**
   * Gets the terms that, when found in the {@code error_description} of an {@code access_denied} error response
   * (case-insensitive), mean that the user cancelled.
   *
   * @return the cancel terms
   */
  public @NonNull List<String> getCancelTerms() {
    return this.cancelTerms;
  }

  /**
   * Assigns the terms that, when found in the {@code error_description} of an {@code access_denied} error response
   * (case-insensitive), mean that the user cancelled.
   *
   * @param cancelTerms the cancel terms
   */
  public void setCancelTerms(final @NonNull List<String> cancelTerms) {
    this.cancelTerms = cancelTerms;
  }

  /**
   * Plain-text user message templates, where the key is the language tag. Sent to OPs that support user messages but
   * not Markdown.
   */
  private @NonNull Map<String, Resource> plainUserMessageTemplate = new LinkedHashMap<>(Map.of(
      "sv", new ClassPathResource("user-message-plain_sv.txt"),
      "en", new ClassPathResource("user-message-plain_en.txt")));

  /**
   * Gets the plain-text user message templates, where the key is the language tag.
   *
   * @return the plain user message template
   */
  public @NonNull Map<String, Resource> getPlainUserMessageTemplate() {
    return this.plainUserMessageTemplate;
  }

  /**
   * Assigns the plain-text user message templates, where the key is the language tag.
   *
   * @param plainUserMessageTemplate the plain user message template
   */
  public void setPlainUserMessageTemplate(final @NonNull Map<String, Resource> plainUserMessageTemplate) {
    this.plainUserMessageTemplate = plainUserMessageTemplate;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() {
    Assert.hasText(this.subjectType, "rp.subject-type must be assigned");
    Assert.isTrue("public".equals(this.subjectType) || "pairwise".equals(this.subjectType),
        "rp.subject-type must be 'public' or 'pairwise'");
    Assert.isTrue(!this.entityConfigurationLifetime.isNegative() && !this.entityConfigurationLifetime.isZero(),
        "rp.entity-configuration-lifetime must be positive");
    for (final ProviderConfig provider : this.providers) {
      provider.afterPropertiesSet();
    }
    this.discovery.afterPropertiesSet();
    this.federation.afterPropertiesSet();
  }

  /**
   * The RP credentials.
   */
  public static class Credentials {

    /**
     * The OIDC signing credential. Defaults to {@code sp.credential.sign}.
     */
    private @Nullable PkiCredentialConfiguration sign;

    /**
     * Gets the OIDC signing credential.
     *
     * @return the OIDC signing credential
     */
    public @Nullable PkiCredentialConfiguration getSign() {
      return this.sign;
    }

    /**
     * Assigns the OIDC signing credential.
     *
     * @param sign the OIDC signing credential
     */
    public void setSign(final @Nullable PkiCredentialConfiguration sign) {
      this.sign = sign;
    }

    /**
     * The OIDC decryption credential. Defaults to {@code sp.credential.decrypt}.
     */
    private @Nullable PkiCredentialConfiguration decrypt;

    /**
     * Gets the OIDC decryption credential.
     *
     * @return the OIDC decryption credential
     */
    public @Nullable PkiCredentialConfiguration getDecrypt() {
      return this.decrypt;
    }

    /**
     * Assigns the OIDC decryption credential.
     *
     * @param decrypt the OIDC decryption credential
     */
    public void setDecrypt(final @Nullable PkiCredentialConfiguration decrypt) {
      this.decrypt = decrypt;
    }

    /**
     * The federation entity key used to sign the entity configuration. Required when federation is enabled. Defaults
     * to the OIDC signing credential when federation is disabled.
     */
    private @Nullable PkiCredentialConfiguration federation;

    /**
     * Gets the federation entity key used to sign the entity configuration.
     *
     * @return the federation
     */
    public @Nullable PkiCredentialConfiguration getFederation() {
      return this.federation;
    }

    /**
     * Assigns the federation entity key used to sign the entity configuration.
     *
     * @param federation the federation
     */
    public void setFederation(final @Nullable PkiCredentialConfiguration federation) {
      this.federation = federation;
    }
  }

  /**
   * Encryption settings for ID tokens and UserInfo responses.
   */
  public static class Encryption {

    /**
     * Whether ID tokens and UserInfo responses should be encrypted.
     */
    private boolean enabled = false;

    /**
     * Tells whether ID tokens and UserInfo responses should be encrypted.
     *
     * @return whether ID tokens and UserInfo responses should be encrypted
     */
    public boolean isEnabled() {
      return this.enabled;
    }

    /**
     * Assigns whether ID tokens and UserInfo responses should be encrypted.
     *
     * @param enabled whether ID tokens and UserInfo responses should be encrypted
     */
    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }

    /**
     * The key management algorithm for ID tokens. Defaults to a value matching the decryption key's type.
     */
    private @Nullable String idTokenAlg;

    /**
     * Gets the key management algorithm for ID tokens.
     *
     * @return the key management algorithm for ID tokens
     */
    public @Nullable String getIdTokenAlg() {
      return this.idTokenAlg;
    }

    /**
     * Assigns the key management algorithm for ID tokens.
     *
     * @param idTokenAlg the key management algorithm for ID tokens
     */
    public void setIdTokenAlg(final @Nullable String idTokenAlg) {
      this.idTokenAlg = idTokenAlg;
    }

    /**
     * The content encryption algorithm for ID tokens.
     */
    private @Nullable String idTokenEnc;

    /**
     * Gets the content encryption algorithm for ID tokens.
     *
     * @return the content encryption algorithm for ID tokens
     */
    public @Nullable String getIdTokenEnc() {
      return this.idTokenEnc;
    }

    /**
     * Assigns the content encryption algorithm for ID tokens.
     *
     * @param idTokenEnc the content encryption algorithm for ID tokens
     */
    public void setIdTokenEnc(final @Nullable String idTokenEnc) {
      this.idTokenEnc = idTokenEnc;
    }

    /**
     * The key management algorithm for UserInfo responses. Defaults to a value matching the decryption key's type.
     */
    private @Nullable String userinfoAlg;

    /**
     * Gets the key management algorithm for UserInfo responses.
     *
     * @return the key management algorithm for UserInfo responses
     */
    public @Nullable String getUserinfoAlg() {
      return this.userinfoAlg;
    }

    /**
     * Assigns the key management algorithm for UserInfo responses.
     *
     * @param userinfoAlg the key management algorithm for UserInfo responses
     */
    public void setUserinfoAlg(final @Nullable String userinfoAlg) {
      this.userinfoAlg = userinfoAlg;
    }

    /**
     * The content encryption algorithm for UserInfo responses.
     */
    private @Nullable String userinfoEnc;

    /**
     * Gets the content encryption algorithm for UserInfo responses.
     *
     * @return the content encryption algorithm for UserInfo responses
     */
    public @Nullable String getUserinfoEnc() {
      return this.userinfoEnc;
    }

    /**
     * Assigns the content encryption algorithm for UserInfo responses.
     *
     * @param userinfoEnc the content encryption algorithm for UserInfo responses
     */
    public void setUserinfoEnc(final @Nullable String userinfoEnc) {
      this.userinfoEnc = userinfoEnc;
    }
  }

  /**
   * Overrides for the RP metadata.
   */
  public static class Metadata {

    /**
     * The client names, given as {@code <lang>-<name>}. Defaults to {@code sp.metadata.service-names}.
     */
    private @Nullable List<LocalizedString> clientNames;

    /**
     * Gets the client names, given as {@code <lang>-<name>}.
     *
     * @return the client names, given as {@code <lang>-<name>}
     */
    public @Nullable List<LocalizedString> getClientNames() {
      return this.clientNames;
    }

    /**
     * Assigns the client names, given as {@code <lang>-<name>}.
     *
     * @param clientNames the client names, given as {@code <lang>-<name>}
     */
    public void setClientNames(final @Nullable List<LocalizedString> clientNames) {
      this.clientNames = clientNames;
    }

    /**
     * The logotype URI. Defaults to the first logo under {@code sp.metadata.uiinfo.logos}.
     */
    private @Nullable String logoUri;

    /**
     * Gets the logotype URI.
     *
     * @return the logotype URI
     */
    public @Nullable String getLogoUri() {
      return this.logoUri;
    }

    /**
     * Assigns the logotype URI.
     *
     * @param logoUri the logotype URI
     */
    public void setLogoUri(final @Nullable String logoUri) {
      this.logoUri = logoUri;
    }

    /**
     * The client URI (home page). Defaults to the start page of the application.
     */
    private @Nullable String clientUri;

    /**
     * Gets the client URI (home page).
     *
     * @return the client URI (home page)
     */
    public @Nullable String getClientUri() {
      return this.clientUri;
    }

    /**
     * Assigns the client URI (home page).
     *
     * @param clientUri the client URI (home page)
     */
    public void setClientUri(final @Nullable String clientUri) {
      this.clientUri = clientUri;
    }

    /**
     * Contact email addresses. Defaults to the email addresses of the support and technical contact persons under
     * {@code sp.metadata.contact-persons}.
     */
    private @Nullable List<String> contacts;

    /**
     * Gets the contact email addresses.
     *
     * @return the contact email addresses
     */
    public @Nullable List<String> getContacts() {
      return this.contacts;
    }

    /**
     * Assigns the contact email addresses.
     *
     * @param contacts the contact email addresses
     */
    public void setContacts(final @Nullable List<String> contacts) {
      this.contacts = contacts;
    }

    /**
     * The organization names, given as {@code <lang>-<name>}. Defaults to {@code sp.metadata.organization.names}.
     */
    private @Nullable List<LocalizedString> organizationNames;

    /**
     * Gets the organization names, given as {@code <lang>-<name>}.
     *
     * @return the organization names, given as {@code <lang>-<name>}
     */
    public @Nullable List<LocalizedString> getOrganizationNames() {
      return this.organizationNames;
    }

    /**
     * Assigns the organization names, given as {@code <lang>-<name>}.
     *
     * @param organizationNames the organization names, given as {@code <lang>-<name>}
     */
    public void setOrganizationNames(final @Nullable List<LocalizedString> organizationNames) {
      this.organizationNames = organizationNames;
    }

    /**
     * The organization identifier. Defaults to {@code urn:glue:iso6523:0007:<number>} where the number is
     * {@code sp.metadata.organization.number}.
     */
    private @Nullable String organizationIdentifier;

    /**
     * Gets the organization identifier.
     *
     * @return the organization identifier
     */
    public @Nullable String getOrganizationIdentifier() {
      return this.organizationIdentifier;
    }

    /**
     * Assigns the organization identifier.
     *
     * @param organizationIdentifier the organization identifier
     */
    public void setOrganizationIdentifier(final @Nullable String organizationIdentifier) {
      this.organizationIdentifier = organizationIdentifier;
    }
  }

  /**
   * OpenID Federation settings.
   */
  public static class Federation implements InitializingBean {

    /**
     * Whether the RP is a member of an OpenID Federation.
     */
    private boolean enabled = false;

    /**
     * Tells whether the RP is a member of an OpenID Federation.
     *
     * @return whether the RP is a member of an OpenID Federation
     */
    public boolean isEnabled() {
      return this.enabled;
    }

    /**
     * Assigns whether the RP is a member of an OpenID Federation.
     *
     * @param enabled whether the RP is a member of an OpenID Federation
     */
    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }

    /**
     * The trust anchor.
     */
    @NestedConfigurationProperty
    private @NonNull TrustAnchor trustAnchor = new TrustAnchor();

    /**
     * Gets the trust anchor.
     *
     * @return the trust anchor
     */
    public @NonNull TrustAnchor getTrustAnchor() {
      return this.trustAnchor;
    }

    /**
     * The entities whose subordinate listing endpoints are asked for OPs. Defaults to the trust anchor.
     */
    private @NonNull List<ListingSource> listingSources = new ArrayList<>();

    /**
     * Gets the entities whose subordinate listing endpoints are asked for OPs.
     *
     * @return the listing sources
     */
    public @NonNull List<ListingSource> getListingSources() {
      return this.listingSources;
    }

    /**
     * Assigns the entities whose subordinate listing endpoints are asked for OPs.
     *
     * @param listingSources the listing sources
     */
    public void setListingSources(final @NonNull List<ListingSource> listingSources) {
      this.listingSources = listingSources;
    }

    /**
     * The authority hints of the RP's entity configuration (the RP's immediate superiors).
     */
    private @NonNull List<String> authorityHints = new ArrayList<>();

    /**
     * Gets the authority hints of the RP's entity configuration (the RP's immediate superiors).
     *
     * @return the authority hints
     */
    public @NonNull List<String> getAuthorityHints() {
      return this.authorityHints;
    }

    /**
     * Assigns the authority hints of the RP's entity configuration (the RP's immediate superiors).
     *
     * @param authorityHints the authority hints
     */
    public void setAuthorityHints(final @NonNull List<String> authorityHints) {
      this.authorityHints = authorityHints;
    }

    /**
     * The issuers of the RP's own trust marks.
     */
    private @NonNull List<TrustMarkIssuer> trustMarkIssuers = new ArrayList<>();

    /**
     * Gets the issuers of the RP's own trust marks.
     *
     * @return the issuers of the RP's own trust marks
     */
    public @NonNull List<TrustMarkIssuer> getTrustMarkIssuers() {
      return this.trustMarkIssuers;
    }

    /**
     * Assigns the issuers of the RP's own trust marks.
     *
     * @param trustMarkIssuers the issuers of the RP's own trust marks
     */
    public void setTrustMarkIssuers(final @NonNull List<TrustMarkIssuer> trustMarkIssuers) {
      this.trustMarkIssuers = trustMarkIssuers;
    }

    /**
     * How often OPs are listed and resolved, and the RP's trust marks are checked for renewal.
     */
    private @NonNull Duration refreshInterval = Duration.ofHours(1);

    /**
     * Gets how often OPs are listed and resolved, and the RP's trust marks are checked for renewal.
     *
     * @return the refresh interval
     */
    public @NonNull Duration getRefreshInterval() {
      return this.refreshInterval;
    }

    /**
     * Assigns how often OPs are listed and resolved, and the RP's trust marks are checked for renewal.
     *
     * @param refreshInterval the refresh interval
     */
    public void setRefreshInterval(final @NonNull Duration refreshInterval) {
      this.refreshInterval = refreshInterval;
    }

    /**
     * How soon a failed listing, resolve or trust mark fetch is retried.
     */
    private @NonNull Duration retryInterval = Duration.ofMinutes(5);

    /**
     * Gets how soon a failed listing, resolve or trust mark fetch is retried.
     *
     * @return the retry interval
     */
    public @NonNull Duration getRetryInterval() {
      return this.retryInterval;
    }

    /**
     * Assigns how soon a failed listing, resolve or trust mark fetch is retried.
     *
     * @param retryInterval the retry interval
     */
    public void setRetryInterval(final @NonNull Duration retryInterval) {
      this.retryInterval = retryInterval;
    }

    /**
     * Rules telling which trust marks an OP found through the federation must have for the {@code acr} values it
     * issues. An {@code acr} that no rule covers needs no trust mark.
     */
    private @NonNull List<LoaTrustMarkRule> loaTrustMarks = defaultLoaTrustMarkRules();

    /**
     * Gets the rules telling which trust marks an OP found through the federation must have for the {@code acr} values
     * it issues.
     *
     * @return the LoA trust marks
     */
    public @NonNull List<LoaTrustMarkRule> getLoaTrustMarks() {
      return this.loaTrustMarks;
    }

    /**
     * Assigns the rules telling which trust marks an OP found through the federation must have for the {@code acr}
     * values it issues.
     *
     * @param loaTrustMarks the LoA trust marks
     */
    public void setLoaTrustMarks(final @NonNull List<LoaTrustMarkRule> loaTrustMarks) {
      this.loaTrustMarks = loaTrustMarks;
    }

    /**
     * Gets the listing sources, or the trust anchor if none are configured.
     *
     * @return the listing sources
     */
    public @NonNull List<ListingSource> getEffectiveListingSources() {
      if (!this.listingSources.isEmpty()) {
        return this.listingSources;
      }
      final ListingSource source = new ListingSource();
      source.setEntityId(this.trustAnchor.getEntityId());
      return List.of(source);
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      if (!this.enabled) {
        return;
      }
      Assert.hasText(this.trustAnchor.getEntityId(),
          "rp.federation.trust-anchor.entity-id must be assigned when federation is enabled");
      Assert.isTrue(StringUtils.hasText(this.trustAnchor.getJwks()) || this.trustAnchor.getJwksResource() != null,
          "rp.federation.trust-anchor.jwks or jwks-resource (the trust anchor's federation key) must be assigned "
              + "when federation is enabled");
      Assert.isTrue(this.refreshInterval.isPositive(), "rp.federation.refresh-interval must be positive");
      Assert.isTrue(this.retryInterval.isPositive(), "rp.federation.retry-interval must be positive");
      for (final ListingSource source : this.listingSources) {
        Assert.hasText(source.getEntityId(), "rp.federation.listing-sources[].entity-id must be assigned");
      }
      for (final TrustMarkIssuer issuer : this.trustMarkIssuers) {
        Assert.hasText(issuer.getEntityId(), "rp.federation.trust-mark-issuers[].entity-id must be assigned");
        Assert.notEmpty(issuer.getTrustMarkTypes(),
            "rp.federation.trust-mark-issuers[].trust-mark-types must be assigned");
      }
      for (final LoaTrustMarkRule rule : this.loaTrustMarks) {
        Assert.notEmpty(rule.getAcr(), "rp.federation.loa-trust-marks[].acr must be assigned");
        Assert.notEmpty(rule.getTrustMarks(), "rp.federation.loa-trust-marks[].trust-marks must be assigned");
      }
    }

    /**
     * Gets the default rules for the Level of Assurance trust mark check (Sweden Connect).
     *
     * @return the default rules
     */
    public static @NonNull List<LoaTrustMarkRule> defaultLoaTrustMarkRules() {
      final String tm = "https://id.swedenconnect.se/loa/";
      final String loa = "http://id.elegnamnden.se/loa/1.0/";
      final String scLoa = "http://id.swedenconnect.se/loa/1.0/";
      final List<LoaTrustMarkRule> rules = new ArrayList<>();
      for (final String level : List.of("loa2", "loa3", "loa4")) {
        rules.add(LoaTrustMarkRule.of(List.of(loa + level), List.of(tm + level)));
        rules.add(LoaTrustMarkRule.of(List.of(scLoa + level + "-nonresident"),
            List.of(tm + "nonresident", tm + level)));
      }
      rules.add(LoaTrustMarkRule.of(List.of(
          loa + "eidas-low", loa + "eidas-nf-low", loa + "eidas-sub", loa + "eidas-nf-sub",
          loa + "eidas-high", loa + "eidas-nf-high"), List.of(tm + "eidas")));
      return rules;
    }
  }

  /**
   * The trust anchor.
   */
  public static class TrustAnchor {

    /**
     * The entity identifier of the trust anchor.
     */
    private @Nullable String entityId;

    /**
     * Gets the entity identifier of the trust anchor.
     *
     * @return the entity identifier of the trust anchor
     */
    public @Nullable String getEntityId() {
      return this.entityId;
    }

    /**
     * Assigns the entity identifier of the trust anchor.
     *
     * @param entityId the entity identifier of the trust anchor
     */
    public void setEntityId(final @Nullable String entityId) {
      this.entityId = entityId;
    }

    /**
     * The trust anchor's federation key(s) given inline as a JWK or a JWK set (JSON).
     */
    private @Nullable String jwks;

    /**
     * Gets the trust anchor's federation key(s) given inline as a JWK or a JWK set (JSON).
     *
     * @return the JWKs
     */
    public @Nullable String getJwks() {
      return this.jwks;
    }

    /**
     * Assigns the trust anchor's federation key(s) given inline as a JWK or a JWK set (JSON).
     *
     * @param jwks the JWKs
     */
    public void setJwks(final @Nullable String jwks) {
      this.jwks = jwks;
    }

    /**
     * A resource holding the trust anchor's federation key(s) as a JWK or a JWK set (JSON).
     */
    private @Nullable Resource jwksResource;

    /**
     * Gets a resource holding the trust anchor's federation key(s) as a JWK or a JWK set (JSON).
     *
     * @return the JWKs resource
     */
    public @Nullable Resource getJwksResource() {
      return this.jwksResource;
    }

    /**
     * Assigns a resource holding the trust anchor's federation key(s) as a JWK or a JWK set (JSON).
     *
     * @param jwksResource the JWKs resource
     */
    public void setJwksResource(final @Nullable Resource jwksResource) {
      this.jwksResource = jwksResource;
    }

    /**
     * The resolve endpoint. Defaults to the {@code federation_resolve_endpoint} of the trust anchor's entity
     * configuration.
     */
    private @Nullable String resolveEndpoint;

    /**
     * Gets the resolve endpoint.
     *
     * @return the resolve endpoint
     */
    public @Nullable String getResolveEndpoint() {
      return this.resolveEndpoint;
    }

    /**
     * Assigns the resolve endpoint.
     *
     * @param resolveEndpoint the resolve endpoint
     */
    public void setResolveEndpoint(final @Nullable String resolveEndpoint) {
      this.resolveEndpoint = resolveEndpoint;
    }
  }

  /**
   * An entity whose subordinate listing endpoint is asked for OPs.
   */
  public static class ListingSource {

    /**
     * The entity identifier.
     */
    private @Nullable String entityId;

    /**
     * Gets the entity identifier.
     *
     * @return the entity identifier
     */
    public @Nullable String getEntityId() {
      return this.entityId;
    }

    /**
     * Assigns the entity identifier.
     *
     * @param entityId the entity identifier
     */
    public void setEntityId(final @Nullable String entityId) {
      this.entityId = entityId;
    }

    /**
     * The listing endpoint. Defaults to the {@code federation_list_endpoint} of the entity's metadata.
     */
    private @Nullable String listEndpoint;

    /**
     * Gets the listing endpoint.
     *
     * @return the listing endpoint
     */
    public @Nullable String getListEndpoint() {
      return this.listEndpoint;
    }

    /**
     * Assigns the listing endpoint.
     *
     * @param listEndpoint the listing endpoint
     */
    public void setListEndpoint(final @Nullable String listEndpoint) {
      this.listEndpoint = listEndpoint;
    }
  }

  /**
   * An issuer of the RP's trust marks.
   */
  public static class TrustMarkIssuer {

    /**
     * The entity identifier of the trust mark issuer.
     */
    private @Nullable String entityId;

    /**
     * Gets the entity identifier of the trust mark issuer.
     *
     * @return the entity identifier of the trust mark issuer
     */
    public @Nullable String getEntityId() {
      return this.entityId;
    }

    /**
     * Assigns the entity identifier of the trust mark issuer.
     *
     * @param entityId the entity identifier of the trust mark issuer
     */
    public void setEntityId(final @Nullable String entityId) {
      this.entityId = entityId;
    }

    /**
     * The trust mark endpoint. Defaults to the {@code federation_trust_mark_endpoint} of the issuer's metadata.
     */
    private @Nullable String trustMarkEndpoint;

    /**
     * Gets the trust mark endpoint.
     *
     * @return the trust mark endpoint
     */
    public @Nullable String getTrustMarkEndpoint() {
      return this.trustMarkEndpoint;
    }

    /**
     * Assigns the trust mark endpoint.
     *
     * @param trustMarkEndpoint the trust mark endpoint
     */
    public void setTrustMarkEndpoint(final @Nullable String trustMarkEndpoint) {
      this.trustMarkEndpoint = trustMarkEndpoint;
    }

    /**
     * The trust mark types to request for the RP.
     */
    private @NonNull List<String> trustMarkTypes = new ArrayList<>();

    /**
     * Gets the trust mark types to request for the RP.
     *
     * @return the trust mark types to request for the RP
     */
    public @NonNull List<String> getTrustMarkTypes() {
      return this.trustMarkTypes;
    }

    /**
     * Assigns the trust mark types to request for the RP.
     *
     * @param trustMarkTypes the trust mark types to request for the RP
     */
    public void setTrustMarkTypes(final @NonNull List<String> trustMarkTypes) {
      this.trustMarkTypes = trustMarkTypes;
    }
  }

  /**
   * A rule for the Level of Assurance trust mark check: an OP that issues one of the {@code acr} values must have all
   * the listed trust marks.
   */
  public static class LoaTrustMarkRule {

    /**
     * The {@code acr} values that the rule covers.
     */
    private @NonNull List<String> acr = new ArrayList<>();

    /**
     * Gets the {@code acr} values that the rule covers.
     *
     * @return the {@code acr} values that the rule covers
     */
    public @NonNull List<String> getAcr() {
      return this.acr;
    }

    /**
     * Assigns the {@code acr} values that the rule covers.
     *
     * @param acr the {@code acr} values that the rule covers
     */
    public void setAcr(final @NonNull List<String> acr) {
      this.acr = acr;
    }

    /**
     * The trust mark types that the OP must have (all of them).
     */
    private @NonNull List<String> trustMarks = new ArrayList<>();

    /**
     * Gets the trust mark types that the OP must have (all of them).
     *
     * @return the trust mark types that the OP must have (all of them)
     */
    public @NonNull List<String> getTrustMarks() {
      return this.trustMarks;
    }

    /**
     * Assigns the trust mark types that the OP must have (all of them).
     *
     * @param trustMarks the trust mark types that the OP must have (all of them)
     */
    public void setTrustMarks(final @NonNull List<String> trustMarks) {
      this.trustMarks = trustMarks;
    }

    /**
     * Creates a rule.
     *
     * @param acr the {@code acr} values
     * @param trustMarks the required trust mark types
     * @return a rule
     */
    public static @NonNull LoaTrustMarkRule of(final @NonNull List<String> acr,
        final @NonNull List<String> trustMarks) {
      final LoaTrustMarkRule rule = new LoaTrustMarkRule();
      rule.setAcr(new ArrayList<>(acr));
      rule.setTrustMarks(new ArrayList<>(trustMarks));
      return rule;
    }
  }

  /**
   * A manually configured OpenID Provider.
   */
  public static class ProviderConfig implements InitializingBean {

    /**
     * The OP's issuer identifier.
     */
    private @Nullable String issuer;

    /**
     * Gets the OP's issuer identifier.
     *
     * @return the OP's issuer identifier
     */
    public @Nullable String getIssuer() {
      return this.issuer;
    }

    /**
     * Assigns the OP's issuer identifier.
     *
     * @param issuer the OP's issuer identifier
     */
    public void setIssuer(final @Nullable String issuer) {
      this.issuer = issuer;
    }

    /**
     * The OP's discovery document given inline as JSON. When given, nothing is fetched for the OP.
     */
    private @Nullable String discoveryDocument;

    /**
     * Gets the OP's discovery document given inline as JSON.
     *
     * @return the OP's discovery document given inline as JSON
     */
    public @Nullable String getDiscoveryDocument() {
      return this.discoveryDocument;
    }

    /**
     * Assigns the OP's discovery document given inline as JSON.
     *
     * @param discoveryDocument the OP's discovery document given inline as JSON
     */
    public void setDiscoveryDocument(final @Nullable String discoveryDocument) {
      this.discoveryDocument = discoveryDocument;
    }

    /**
     * A resource holding the OP's discovery document. When given, nothing is fetched for the OP.
     */
    private @Nullable Resource discoveryDocumentResource;

    /**
     * Gets a resource holding the OP's discovery document.
     *
     * @return a resource holding the OP's discovery document
     */
    public @Nullable Resource getDiscoveryDocumentResource() {
      return this.discoveryDocumentResource;
    }

    /**
     * Assigns a resource holding the OP's discovery document.
     *
     * @param discoveryDocumentResource a resource holding the OP's discovery document
     */
    public void setDiscoveryDocumentResource(final @Nullable Resource discoveryDocumentResource) {
      this.discoveryDocumentResource = discoveryDocumentResource;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.hasText(this.issuer, "rp.providers[].issuer must be assigned");
      Assert.isTrue(!(StringUtils.hasText(this.discoveryDocument) && this.discoveryDocumentResource != null),
          "rp.providers[].discovery-document and discovery-document-resource can not both be assigned");
    }
  }

  /**
   * Settings for how OPs are listed and refreshed.
   */
  public static class Discovery implements InitializingBean {

    /**
     * How often discovery documents are refreshed.
     */
    private @NonNull Duration refreshInterval = Duration.ofHours(1);

    /**
     * Gets how often discovery documents are refreshed.
     *
     * @return how often discovery documents are refreshed
     */
    public @NonNull Duration getRefreshInterval() {
      return this.refreshInterval;
    }

    /**
     * Assigns how often discovery documents are refreshed.
     *
     * @param refreshInterval how often discovery documents are refreshed
     */
    public void setRefreshInterval(final @NonNull Duration refreshInterval) {
      this.refreshInterval = refreshInterval;
    }

    /**
     * How soon a failed fetch is retried.
     */
    private @NonNull Duration retryInterval = Duration.ofMinutes(5);

    /**
     * Gets how soon a failed fetch is retried.
     *
     * @return how soon a failed fetch is retried
     */
    public @NonNull Duration getRetryInterval() {
      return this.retryInterval;
    }

    /**
     * Assigns how soon a failed fetch is retried.
     *
     * @param retryInterval how soon a failed fetch is retried
     */
    public void setRetryInterval(final @NonNull Duration retryInterval) {
      this.retryInterval = retryInterval;
    }

    /**
     * Issuers of OPs that should not be listed.
     */
    private @NonNull List<String> blackList = new ArrayList<>();

    /**
     * Gets the issuers of OPs that should not be listed.
     *
     * @return the issuers of OPs that should not be listed
     */
    public @NonNull List<String> getBlackList() {
      return this.blackList;
    }

    /**
     * Assigns the issuers of OPs that should not be listed.
     *
     * @param blackList the issuers of OPs that should not be listed
     */
    public void setBlackList(final @NonNull List<String> blackList) {
      this.blackList = blackList;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.isTrue(this.refreshInterval.isPositive(), "rp.discovery.refresh-interval must be positive");
      Assert.isTrue(this.retryInterval.isPositive(), "rp.discovery.retry-interval must be positive");
    }
  }

}
