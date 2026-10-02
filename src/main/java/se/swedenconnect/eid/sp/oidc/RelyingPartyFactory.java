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
package se.swedenconnect.eid.sp.oidc;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.CredentialsConfiguration.PkiCredentialConfiguration;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.security.credential.PkiCredential;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Builds the {@link RelyingParty} from the configuration, deriving the RP metadata from the SAML metadata settings,
 * and makes sure that the result meets the Sweden Connect requirements. Any violation stops startup.
 *
 * @author Martin Lindström
 */
public final class RelyingPartyFactory {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(RelyingPartyFactory.class);

  /** Prefix for organization identifiers built from a Swedish organization number. */
  public static final @NonNull String ORGANIZATION_IDENTIFIER_PREFIX = "urn:glue:iso6523:0007:";

  /** The {@code organization_name} metadata parameter. */
  public static final @NonNull String ORGANIZATION_NAME = "organization_name";

  /** The {@code organization_identifier} metadata parameter. */
  public static final @NonNull String ORGANIZATION_IDENTIFIER = "organization_identifier";

  /** Pattern for a Swedish organization number. */
  private static final Pattern ORGANIZATION_NUMBER = Pattern.compile("^\\d{10}$");

  // Hidden constructor
  private RelyingPartyFactory() {
  }

  /**
   * Builds the Relying Party.
   *
   * @param sp the SAML SP settings (shared settings and metadata defaults)
   * @param rp the OIDC RP settings
   * @param contextPath the servlet context path
   * @param credentialLoader function that loads a credential from its configuration
   * @return the {@link RelyingParty}
   * @throws IllegalStateException if the configuration does not meet the requirements
   */
  public static @NonNull RelyingParty create(final @NonNull SpConfigurationProperties sp,
      final @NonNull RpConfigurationProperties rp, final @NonNull String contextPath,
      final @NonNull Function<PkiCredentialConfiguration, PkiCredential> credentialLoader) {

    final String appUri = applicationUri(sp.getBaseUri(), contextPath);
    final String entityId = StringUtils.hasText(rp.getEntityId()) ? rp.getEntityId() : appUri;
    final URI redirectUri = URI.create(appUri + RelyingParty.CALLBACK_PATH);

    // Credentials
    //
    final PkiCredential signCredential = credentialLoader.apply(
        Optional.ofNullable(rp.getCredential().getSign()).orElse(sp.getCredential().getSign()));
    final PkiCredentialConfiguration decryptConfig =
        Optional.ofNullable(rp.getCredential().getDecrypt()).orElse(sp.getCredential().getDecrypt());
    final PkiCredential decryptCredential = decryptConfig != null ? credentialLoader.apply(decryptConfig) : null;

    final PkiCredential federationCredential;
    if (rp.getCredential().getFederation() != null) {
      federationCredential = credentialLoader.apply(rp.getCredential().getFederation());
    }
    else if (rp.getFederation().isEnabled()) {
      throw new IllegalStateException(
          "rp.credential.federation must be assigned when OpenID Federation is enabled (rp.federation.enabled)");
    }
    else {
      federationCredential = signCredential;
    }

    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setRedirectionURI(redirectUri);
    metadata.setResponseTypes(Set.of(ResponseType.CODE));
    metadata.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE));
    metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    try {
      metadata.setSubjectType(SubjectType.parse(rp.getSubjectType()));
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException e) {
      throw new IllegalStateException("Invalid rp.subject-type - " + e.getMessage(), e);
    }
    if (rp.getFederation().isEnabled()) {
      metadata.setClientRegistrationTypes(List.of(ClientRegistrationType.AUTOMATIC));
    }

    // Algorithms and keys
    //
    final com.nimbusds.jose.JWSAlgorithm signAlg = JoseSupport.signatureAlgorithm(signCredential);
    metadata.setRequestObjectJWSAlg(signAlg);
    metadata.setTokenEndpointAuthJWSAlg(signAlg);

    final List<JWK> keys = new ArrayList<>();
    keys.add(JoseSupport.publicJwk(signCredential, KeyUse.SIGNATURE, signAlg));

    final RpConfigurationProperties.Encryption encryption = rp.getEncryption();
    if (encryption.isEnabled()) {
      if (decryptCredential == null) {
        throw new IllegalStateException("Encryption is enabled (rp.encryption.enabled) but no decryption "
            + "credential is configured (rp.credential.decrypt or sp.credential.decrypt)");
      }
      metadata.setIDTokenJWEAlg(keyManagementAlgorithm(encryption.getIdTokenAlg(), "rp.encryption.id-token-alg",
          decryptCredential));
      metadata.setIDTokenJWEEnc(contentEncryptionAlgorithm(encryption.getIdTokenEnc(), "rp.encryption.id-token-enc"));
      metadata.setUserInfoJWEAlg(keyManagementAlgorithm(encryption.getUserinfoAlg(), "rp.encryption.userinfo-alg",
          decryptCredential));
      metadata.setUserInfoJWEEnc(
          contentEncryptionAlgorithm(encryption.getUserinfoEnc(), "rp.encryption.userinfo-enc"));
      keys.add(JoseSupport.publicJwk(decryptCredential, KeyUse.ENCRYPTION, null));
    }
    metadata.setJWKSet(new JWKSet(keys));

    // Descriptive values
    //
    final MetadataConfiguration samlMetadata = sp.getMetadata();
    final RpConfigurationProperties.Metadata overrides = rp.getMetadata();

    final List<LocalizedString> clientNames = Optional.ofNullable(overrides.getClientNames())
        .filter(l -> !l.isEmpty())
        .orElse(Optional.ofNullable(samlMetadata.getServiceNames()).orElse(List.of()));
    for (final LocalizedString name : clientNames) {
      metadata.setName(name.getLocalString(), langTag(name.getLanguage()));
    }
    for (final String lang : List.of("sv", "en")) {
      if (clientNames.stream().noneMatch(n -> lang.equals(n.getLanguage()) && StringUtils.hasText(n.getLocalString()))) {
        throw new IllegalStateException(("The RP client name must be given in Swedish and English - '%s' is missing "
            + "(rp.metadata.client-names or sp.metadata.service-names)").formatted(lang));
      }
    }

    final String logoUri = Optional.ofNullable(overrides.getLogoUri())
        .filter(StringUtils::hasText)
        .orElseGet(() -> Optional.ofNullable(samlMetadata.getUiinfo())
            .map(MetadataConfiguration.UIInfoConfig::getLogos)
            .filter(l -> !l.isEmpty())
            .map(l -> l.getFirst().getPath())
            .map(p -> p.startsWith("/") ? appUri + p : p)
            .orElse(null));
    metadata.setLogoURI(httpsUri(logoUri, "logo_uri", "rp.metadata.logo-uri or sp.metadata.uiinfo.logos"));

    final String clientUri = Optional.ofNullable(overrides.getClientUri())
        .filter(StringUtils::hasText)
        .orElse(appUri + "/");
    metadata.setURI(httpsUri(clientUri, "client_uri", "rp.metadata.client-uri or sp.base-uri"));

    final List<String> contacts = Optional.ofNullable(overrides.getContacts())
        .filter(l -> !l.isEmpty())
        .orElseGet(() -> contactEmails(samlMetadata));
    if (contacts.stream().noneMatch(c -> StringUtils.hasText(c) && c.contains("@"))) {
      throw new IllegalStateException("The RP metadata must hold at least one contact email address "
          + "(rp.metadata.contacts or the support/technical contact persons under sp.metadata.contact-persons)");
    }
    metadata.setEmailContacts(contacts);

    final List<LocalizedString> organizationNames = Optional.ofNullable(overrides.getOrganizationNames())
        .filter(l -> !l.isEmpty())
        .orElseGet(() -> Optional.ofNullable(samlMetadata.getOrganization())
            .map(MetadataConfiguration.OrganizationConfig::getNames)
            .orElse(List.of()));
    for (final LocalizedString name : organizationNames) {
      metadata.setCustomField(ORGANIZATION_NAME + "#" + langTag(name.getLanguage()), name.getLocalString());
    }

    final String organizationIdentifier = Optional.ofNullable(overrides.getOrganizationIdentifier())
        .filter(StringUtils::hasText)
        .orElseGet(() -> Optional.ofNullable(samlMetadata.getOrganization())
            .map(MetadataConfiguration.OrganizationConfig::getNumber)
            .map(n -> n.replace("-", "").trim())
            .filter(n -> ORGANIZATION_NUMBER.matcher(n).matches())
            .map(n -> ORGANIZATION_IDENTIFIER_PREFIX + n)
            .orElse(null));
    if (organizationIdentifier != null) {
      metadata.setCustomField(ORGANIZATION_IDENTIFIER, organizationIdentifier);
    }
    else {
      log.debug("No organization_identifier in RP metadata - sp.metadata.organization.number is not ten digits");
    }

    final RelyingParty relyingParty = new RelyingParty(entityId, redirectUri, signCredential, decryptCredential,
        encryption.isEnabled(), federationCredential, metadata);
    log.info("OIDC Relying Party '{}' set up [federation={}, encryption={}]",
        entityId, rp.getFederation().isEnabled(), encryption.isEnabled());
    return relyingParty;
  }

  /**
   * Gets the URI for the application, i.e., the base URI plus the context path.
   *
   * @param baseUri the base URI
   * @param contextPath the context path
   * @return the application URI (with no trailing slash)
   */
  public static @NonNull String applicationUri(final @NonNull String baseUri, final @Nullable String contextPath) {
    final String base = baseUri.endsWith("/") ? baseUri.substring(0, baseUri.length() - 1) : baseUri;
    if (contextPath == null || "/".equals(contextPath) || contextPath.isEmpty()) {
      return base;
    }
    return base + (contextPath.endsWith("/") ? contextPath.substring(0, contextPath.length() - 1) : contextPath);
  }

  /**
   * Gets the email addresses of the support and technical contact persons, without duplicates.
   *
   * @param samlMetadata the SAML metadata settings
   * @return a list of email addresses
   */
  private static @NonNull List<String> contactEmails(final @NonNull MetadataConfiguration samlMetadata) {
    final Set<String> emails = new LinkedHashSet<>();
    final Map<ContactPersonTypeEnumeration, MetadataConfiguration.ContactPersonConfig> persons =
        Optional.ofNullable(samlMetadata.getContactPersons()).orElse(Map.of());
    for (final ContactPersonTypeEnumeration type : List.of(ContactPersonTypeEnumeration.SUPPORT,
        ContactPersonTypeEnumeration.TECHNICAL)) {
      Optional.ofNullable(persons.get(type))
          .map(MetadataConfiguration.ContactPersonConfig::getEmailAddress)
          .filter(StringUtils::hasText)
          .map(e -> e.startsWith("mailto:") ? e.substring("mailto:".length()) : e)
          .ifPresent(emails::add);
    }
    return new ArrayList<>(emails);
  }

  /**
   * Makes sure that the URI is set and uses HTTPS.
   *
   * @param uri the URI
   * @param parameter the metadata parameter
   * @param settings the settings that give the value (for the error message)
   * @return the URI
   */
  private static @NonNull URI httpsUri(final @Nullable String uri, final @NonNull String parameter,
      final @NonNull String settings) {
    if (!StringUtils.hasText(uri)) {
      throw new IllegalStateException("The RP metadata must hold %s (%s)".formatted(parameter, settings));
    }
    final URI result = URI.create(uri);
    if (!"https".equalsIgnoreCase(result.getScheme())) {
      throw new IllegalStateException("The RP metadata parameter %s must be an HTTPS URL - was '%s' (%s)"
          .formatted(parameter, uri, settings));
    }
    return result;
  }

  /**
   * Gets the key management algorithm to declare.
   *
   * @param configured the configured value
   * @param setting the setting name (for the error message)
   * @param decryptCredential the decryption credential
   * @return the algorithm
   */
  private static @NonNull JWEAlgorithm keyManagementAlgorithm(final @Nullable String configured,
      final @NonNull String setting, final @NonNull PkiCredential decryptCredential) {
    if (!StringUtils.hasText(configured)) {
      return JoseSupport.defaultKeyManagementAlgorithm(decryptCredential);
    }
    final JWEAlgorithm alg = JWEAlgorithm.parse(configured);
    if (!JoseSupport.ALLOWED_KEY_MANAGEMENT_ALGORITHMS.contains(alg)) {
      throw new IllegalStateException("%s has the value '%s' - only %s are allowed"
          .formatted(setting, configured, JoseSupport.ALLOWED_KEY_MANAGEMENT_ALGORITHMS));
    }
    if (!JoseSupport.fitsKeyType(alg, decryptCredential)) {
      throw new IllegalStateException("%s has the value '%s' which can not be used with the decryption key (%s)"
          .formatted(setting, configured, decryptCredential.getPublicKey().getAlgorithm()));
    }
    return alg;
  }

  /**
   * Gets the content encryption algorithm to declare.
   *
   * @param configured the configured value
   * @param setting the setting name (for the error message)
   * @return the algorithm
   */
  private static @NonNull EncryptionMethod contentEncryptionAlgorithm(final @Nullable String configured,
      final @NonNull String setting) {
    if (!StringUtils.hasText(configured)) {
      return JoseSupport.DEFAULT_CONTENT_ENCRYPTION_ALGORITHM;
    }
    final EncryptionMethod enc = EncryptionMethod.parse(configured);
    if (!JoseSupport.ALLOWED_CONTENT_ENCRYPTION_ALGORITHMS.contains(enc)) {
      throw new IllegalStateException("%s has the value '%s' - only %s are allowed"
          .formatted(setting, configured, JoseSupport.ALLOWED_CONTENT_ENCRYPTION_ALGORITHMS));
    }
    return enc;
  }

  /**
   * Parses a language tag.
   *
   * @param lang the language
   * @return a {@link LangTag}
   */
  private static @NonNull LangTag langTag(final @NonNull String lang) {
    try {
      return LangTag.parse(lang);
    }
    catch (final LangTagException e) {
      throw new IllegalStateException("Invalid language tag '%s'".formatted(lang), e);
    }
  }

}
