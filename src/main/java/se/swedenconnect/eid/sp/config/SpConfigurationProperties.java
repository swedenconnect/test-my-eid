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
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

import java.util.List;
import java.util.Map;

/**
 * Configuration properties for the SP.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("sp")
public class SpConfigurationProperties implements InitializingBean {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(SpConfigurationProperties.class);

  /**
   * The Base URI for the deployed application.
   */
  private @NonNull String baseUri;

  /**
   * Gets the Base URI for the deployed application.
   *
   * @return the Base URI for the deployed application
   */
  public @NonNull String getBaseUri() {
    return this.baseUri;
  }

  /**
   * Assigns the Base URI for the deployed application.
   *
   * @param baseUri the Base URI for the deployed application
   */
  public void setBaseUri(final @NonNull String baseUri) {
    this.baseUri = baseUri;
  }

  /**
   * Base URI for holder of key profile. Must be set if HoK is enabled.
   */
  private @Nullable String hokBaseUri;

  /**
   * Gets the base URI for holder of key profile.
   *
   * @return the base URI for holder of key profile
   */
  public @Nullable String getHokBaseUri() {
    return this.hokBaseUri;
  }

  /**
   * Assigns the base URI for holder of key profile.
   *
   * @param hokBaseUri the base URI for holder of key profile
   */
  public void setHokBaseUri(final @Nullable String hokBaseUri) {
    this.hokBaseUri = hokBaseUri;
  }

  /**
   * Optional. The Base URI when debugging.
   */
  private @Nullable String debugBaseUri;

  /**
   * Gets the optional.
   *
   * @return the optional
   */
  public @Nullable String getDebugBaseUri() {
    return this.debugBaseUri;
  }

  /**
   * Assigns the optional.
   *
   * @param debugBaseUri the optional
   */
  public void setDebugBaseUri(final @Nullable String debugBaseUri) {
    this.debugBaseUri = debugBaseUri;
  }

  /**
   * Base URI for holder of key profile in debug mode.
   */
  private @Nullable String debugHokBaseUri;

  /**
   * Gets the base URI for holder of key profile in debug mode.
   *
   * @return the base URI for holder of key profile in debug mode
   */
  public @Nullable String getDebugHokBaseUri() {
    return this.debugHokBaseUri;
  }

  /**
   * Assigns the base URI for holder of key profile in debug mode.
   *
   * @param debugHokBaseUri the base URI for holder of key profile in debug mode
   */
  public void setDebugHokBaseUri(final @Nullable String debugHokBaseUri) {
    this.debugHokBaseUri = debugHokBaseUri;
  }

  /**
   * The SAML entity ID for the application.
   */
  private @NonNull String entityId;

  /**
   * Gets the SAML entity ID for the application.
   *
   * @return the SAML entity ID for the application
   */
  public @NonNull String getEntityId() {
    return this.entityId;
  }

  /**
   * Assigns the SAML entity ID for the application.
   *
   * @param entityId the SAML entity ID for the application
   */
  public void setEntityId(final @NonNull String entityId) {
    this.entityId = entityId;
  }

  /**
   * The SAML entity ID for when the application mimics a Signature Service.
   */
  private @Nullable String signEntityId;

  /**
   * Gets the SAML entity ID for when the application mimics a Signature Service.
   *
   * @return the sign entity ID
   */
  public @Nullable String getSignEntityId() {
    return this.signEntityId;
  }

  /**
   * Assigns the SAML entity ID for when the application mimics a Signature Service.
   *
   * @param signEntityId the sign entity ID
   */
  public void setSignEntityId(final @Nullable String signEntityId) {
    this.signEntityId = signEntityId;
  }

  /**
   * The path used during "signing". Only configurable so that the Test my Signature can extend this app.
   */
  private @NonNull String signPath;

  /**
   * Gets the path used during "signing".
   *
   * @return the path used during "signing"
   */
  public @NonNull String getSignPath() {
    return this.signPath;
  }

  /**
   * Assigns the path used during "signing".
   *
   * @param signPath the path used during "signing"
   */
  public void setSignPath(final @NonNull String signPath) {
    this.signPath = signPath;
  }

  /**
   * Whether we are in local debug mode.
   */
  private boolean debugMode = false;

  /**
   * Tells whether we are in local debug mode.
   *
   * @return whether we are in local debug mode
   */
  public boolean isDebugMode() {
    return this.debugMode;
  }

  /**
   * Assigns whether we are in local debug mode.
   *
   * @param debugMode whether we are in local debug mode
   */
  public void setDebugMode(final boolean debugMode) {
    this.debugMode = debugMode;
  }

  /**
   * eIDAS connector configuration.
   */
  @NestedConfigurationProperty
  private @NonNull EidasConnectorConfiguration eidasConnector = new EidasConnectorConfiguration();

  /**
   * Gets the eIDAS connector configuration.
   *
   * @return the eIDAS connector configuration
   */
  public @NonNull EidasConnectorConfiguration getEidasConnector() {
    return this.eidasConnector;
  }

  /**
   * SP credential configuration.
   */
  @NestedConfigurationProperty
  private @NonNull CredentialsConfiguration credential = new CredentialsConfiguration();

  /**
   * Gets the SP credential configuration.
   *
   * @return the SP credential configuration
   */
  public @NonNull CredentialsConfiguration getCredential() {
    return this.credential;
  }

  /**
   * Federation configuration.
   */
  @NestedConfigurationProperty
  private @NonNull FederationConfiguration federation = new FederationConfiguration();

  /**
   * Gets the federation configuration.
   *
   * @return the federation configuration
   */
  public @NonNull FederationConfiguration getFederation() {
    return this.federation;
  }

  /**
   * Configuration for selecting IdP to use.
   */
  @NestedConfigurationProperty
  private @NonNull DiscoveryConfiguration discovery = new DiscoveryConfiguration();

  /**
   * Gets the configuration for selecting IdP to use.
   *
   * @return the configuration for selecting IdP to use
   */
  public @NonNull DiscoveryConfiguration getDiscovery() {
    return this.discovery;
  }

  /**
   * Configuration for mutual TLS (needed for Holder-of-key).
   */
  @NestedConfigurationProperty
  private @NonNull MutualTlsConfiguration mtls = new MutualTlsConfiguration();

  /**
   * Gets the configuration for mutual TLS (needed for Holder-of-key).
   *
   * @return the configuration for mutual TLS (needed for Holder-of-key)
   */
  public @NonNull MutualTlsConfiguration getMtls() {
    return this.mtls;
  }

  /**
   * UI configuration.
   */
  @NestedConfigurationProperty
  private @NonNull UiConfiguration ui = new UiConfiguration();

  /**
   * Gets the UI configuration.
   *
   * @return the UI configuration
   */
  public @NonNull UiConfiguration getUi() {
    return this.ui;
  }

  /**
   * SAML metadata.
   */
  @NestedConfigurationProperty
  private @NonNull MetadataConfiguration metadata = new MetadataConfiguration();

  /**
   * Gets the SAML metadata.
   *
   * @return the SAML metadata
   */
  public @NonNull MetadataConfiguration getMetadata() {
    return this.metadata;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() {
    Assert.hasText(this.baseUri, "sp.base-uri must be assigned");
    Assert.hasText(this.entityId, "sp.entity-id must be assigned");
    //Assert.hasText(this.signEntityId, "sp.sign-entity-id must be assigned");
    if (!StringUtils.hasText(this.signPath)) {
      this.signPath = "/saml2/request/next";
    }

    this.eidasConnector.afterPropertiesSet();
    this.credential.afterPropertiesSet();
    this.federation.afterPropertiesSet();
    this.discovery.afterPropertiesSet();
    this.mtls.afterPropertiesSet();
    this.ui.afterPropertiesSet();
    this.metadata.afterPropertiesSet();
  }

  /**
   * eIDAS specific configuration.
   */
  public static class EidasConnectorConfiguration implements InitializingBean {

    /**
     * The entityID of the eIDAS connector.
     */
    private @NonNull String entityId;

    /**
     * Gets the entityID of the eIDAS connector.
     *
     * @return the entityID of the eIDAS connector
     */
    public @NonNull String getEntityId() {
      return this.entityId;
    }

    /**
     * Assigns the entityID of the eIDAS connector.
     *
     * @param entityId the entityID of the eIDAS connector
     */
    public void setEntityId(final @NonNull String entityId) {
      this.entityId = entityId;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.hasText(this.entityId, "sp.eidas-connector.entity-id must be assigned");
    }
  }

  /**
   * The SP credentials.
   */
  public static class CredentialsConfiguration implements InitializingBean {

    /**
     * The SP signing credentials.
     */
    private @NonNull PkiCredentialConfiguration sign;

    /**
     * Gets the SP signing credentials.
     *
     * @return the SP signing credentials
     */
    public @NonNull PkiCredentialConfiguration getSign() {
      return this.sign;
    }

    /**
     * Assigns the SP signing credentials.
     *
     * @param sign the SP signing credentials
     */
    public void setSign(final @NonNull PkiCredentialConfiguration sign) {
      this.sign = sign;
    }

    /**
     * The SP decryption (encryption) credentials.
     */
    private @NonNull PkiCredentialConfiguration decrypt;

    /**
     * Gets the SP decryption (encryption) credentials.
     *
     * @return the SP decryption (encryption) credentials
     */
    public @NonNull PkiCredentialConfiguration getDecrypt() {
      return this.decrypt;
    }

    /**
     * Assigns the SP decryption (encryption) credentials.
     *
     * @param decrypt the SP decryption (encryption) credentials
     */
    public void setDecrypt(final @NonNull PkiCredentialConfiguration decrypt) {
      this.decrypt = decrypt;
    }

    /**
     * The SP metadata signing credentials.
     */
    private @Nullable PkiCredentialConfiguration mdSign;

    /**
     * Gets the SP metadata signing credentials.
     *
     * @return the SP metadata signing credentials
     */
    public @Nullable PkiCredentialConfiguration getMdSign() {
      return this.mdSign;
    }

    /**
     * Assigns the SP metadata signing credentials.
     *
     * @param mdSign the SP metadata signing credentials
     */
    public void setMdSign(final @Nullable PkiCredentialConfiguration mdSign) {
      this.mdSign = mdSign;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notNull(this.sign, "sp.credential.sign must be assigned");
      Assert.notNull(this.decrypt, "sp.credential.decrypt must be assigned");
    }

    /**
     * Needed to be backwards compatible where we used the {@code file} property instead of {@code resource}.
     */
    public static class PkiCredentialConfiguration extends PkiCredentialConfigurationProperties {

      /**
       * See {@link PkiCredentialConfigurationProperties#setResource(Resource)}.
       *
       * @param resource the file resource pointing at the JKS/P12
       */
      public void setFile(final @NonNull Resource resource) {
        this.setResource(resource);
      }
    }
  }

  /**
   * Configuration for downloading SAML metadata.
   */
  public static class FederationConfiguration implements InitializingBean {

    /**
     * Metadata provider configuration.
     */
    private @NonNull Metadata metadata;

    /**
     * Gets the metadata provider configuration.
     *
     * @return the metadata provider configuration
     */
    public @NonNull Metadata getMetadata() {
      return this.metadata;
    }

    /**
     * Assigns the metadata provider configuration.
     *
     * @param metadata the metadata provider configuration
     */
    public void setMetadata(final @NonNull Metadata metadata) {
      this.metadata = metadata;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notNull(this.metadata, "sp.federation.metadata must be assigned");
      Assert.notNull(this.metadata.getUrl(), "sp.federation.metadata.url must be assigned");
      if (this.metadata.getValidationCertificate() == null) {
        log.warn("sp.federation.metadata.validation-certificate is not assigned");
      }
    }

    /**
     * Settings for the metadata provider.
     */
    public static class Metadata {

      /**
       * URL/resource for downloading metadata.
       */
      private @NonNull Resource url;

      /**
       * Gets the URL/resource for downloading metadata.
       *
       * @return the URL/resource for downloading metadata
       */
      public @NonNull Resource getUrl() {
        return this.url;
      }

      /**
       * Assigns the URL/resource for downloading metadata.
       *
       * @param url the URL/resource for downloading metadata
       */
      public void setUrl(final @NonNull Resource url) {
        this.url = url;
      }

      /**
       * Resource pointing at the metadata validation certificate.
       */
      private @Nullable Resource validationCertificate;

      /**
       * Gets the resource pointing at the metadata validation certificate.
       *
       * @return the resource pointing at the metadata validation certificate
       */
      public @Nullable Resource getValidationCertificate() {
        return this.validationCertificate;
      }

      /**
       * Assigns the resource pointing at the metadata validation certificate.
       *
       * @param validationCertificate the resource pointing at the metadata validation certificate
       */
      public void setValidationCertificate(final @Nullable Resource validationCertificate) {
        this.validationCertificate = validationCertificate;
      }

    }

  }

  /**
   * Configuration for the application UI.
   */
  public static class UiConfiguration implements InitializingBean {

    /**
     * UI languages.
     */
    private @NonNull List<UiLanguage> lang;

    /**
     * Gets the UI languages.
     *
     * @return the UI languages
     */
    public @NonNull List<UiLanguage> getLang() {
      return this.lang;
    }

    /**
     * Assigns the UI languages.
     *
     * @param lang the UI languages
     */
    public void setLang(final @NonNull List<UiLanguage> lang) {
      this.lang = lang;
    }

    /**
     * Templates to user messages for different languages.
     */
    private @NonNull Map<String, Resource> userMessageTemplate;

    /**
     * Gets the templates to user messages for different languages.
     *
     * @return the templates to user messages for different languages
     */
    public @NonNull Map<String, Resource> getUserMessageTemplate() {
      return this.userMessageTemplate;
    }

    /**
     * Assigns the templates to user messages for different languages.
     *
     * @param userMessageTemplate the templates to user messages for different languages
     */
    public void setUserMessageTemplate(final @NonNull Map<String, Resource> userMessageTemplate) {
      this.userMessageTemplate = userMessageTemplate;
    }

    /**
     * Attribute info (for viewing info about received SAML attributes).
     */
    private @NonNull List<AttributeConfig> attributes;

    /**
     * Gets the attribute info (for viewing info about received SAML attributes).
     *
     * @return the attributes
     */
    public @NonNull List<AttributeConfig> getAttributes() {
      return this.attributes;
    }

    /**
     * Assigns the attribute info (for viewing info about received SAML attributes).
     *
     * @param attributes the attributes
     */
    public void setAttributes(final @NonNull List<AttributeConfig> attributes) {
      this.attributes = attributes;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notEmpty(this.lang, "sp.ui must contain at least one language");
      for (final UiLanguage uil : this.lang) {
        Assert.hasText(uil.getLanguageTag(), "sp.ui[].language-tag must be set");
        Assert.hasText(uil.getText(), "sp.ui[].text must be set");
      }
      Assert.notEmpty(this.userMessageTemplate, "sp.ui[].user-message-template must be set");
      Assert.notEmpty(this.attributes, "sp.ui.attributes must be assigned");
      for (final AttributeConfig a : this.attributes) {
        a.afterPropertiesSet();
      }
    }

    /**
     * Attribute configuration.
     */
    public static class AttributeConfig implements InitializingBean {

      /**
       * The name of the SAML attribute.
       */
      private @Nullable String attributeName;

      /**
       * Gets the name of the SAML attribute.
       *
       * @return the name of the SAML attribute
       */
      public @Nullable String getAttributeName() {
        return this.attributeName;
      }

      /**
       * Assigns the name of the SAML attribute.
       *
       * @param attributeName the name of the SAML attribute
       */
      public void setAttributeName(final @Nullable String attributeName) {
        this.attributeName = attributeName;
      }

      /**
       * The name of the OpenID Connect claim that is shown with the same label as the attribute.
       */
      private @Nullable String claimName;

      /**
       * Gets the name of the OpenID Connect claim that is shown with the same label as the attribute.
       *
       * @return the claim name
       */
      public @Nullable String getClaimName() {
        return this.claimName;
      }

      /**
       * Assigns the name of the OpenID Connect claim that is shown with the same label as the attribute.
       *
       * @param claimName the claim name
       */
      public void setClaimName(final @Nullable String claimName) {
        this.claimName = claimName;
      }

      /**
       * The message code for the attribute.
       */
      private @NonNull String messageCode;

      /**
       * Gets the message code for the attribute.
       *
       * @return the message code for the attribute
       */
      public @NonNull String getMessageCode() {
        return this.messageCode;
      }

      /**
       * Assigns the message code for the attribute.
       *
       * @param messageCode the message code for the attribute
       */
      public void setMessageCode(final @NonNull String messageCode) {
        this.messageCode = messageCode;
      }

      /**
       * The message code the attribute if eIDAS is used. If {@code null}, the value for {@code messageCode} is used.
       */
      private @Nullable String messageCodeEidas;

      /**
       * Gets the message code the attribute if eIDAS is used.
       *
       * @return the message code the attribute if eIDAS is used
       */
      public @Nullable String getMessageCodeEidas() {
        return this.messageCodeEidas;
      }

      /**
       * Assigns the message code the attribute if eIDAS is used.
       *
       * @param messageCodeEidas the message code the attribute if eIDAS is used
       */
      public void setMessageCodeEidas(final @Nullable String messageCodeEidas) {
        this.messageCodeEidas = messageCodeEidas;
      }

      /**
       * The message code for the attribute description.
       */
      private @Nullable String descriptionMessageCode;

      /**
       * Gets the message code for the attribute description.
       *
       * @return the message code for the attribute description
       */
      public @Nullable String getDescriptionMessageCode() {
        return this.descriptionMessageCode;
      }

      /**
       * Assigns the message code for the attribute description.
       *
       * @param descriptionMessageCode the message code for the attribute description
       */
      public void setDescriptionMessageCode(final @Nullable String descriptionMessageCode) {
        this.descriptionMessageCode = descriptionMessageCode;
      }

      /**
       * The message code the for attribute description in eIDAS context.
       */
      private @Nullable String descriptionMessageCodeEidas;

      /**
       * Gets the message code the for attribute description in eIDAS context.
       *
       * @return the description message code eidas
       */
      public @Nullable String getDescriptionMessageCodeEidas() {
        return this.descriptionMessageCodeEidas;
      }

      /**
       * Assigns the message code the for attribute description in eIDAS context.
       *
       * @param descriptionMessageCodeEidas the description message code eidas
       */
      public void setDescriptionMessageCodeEidas(final @Nullable String descriptionMessageCodeEidas) {
        this.descriptionMessageCodeEidas = descriptionMessageCodeEidas;
      }

      /**
       * Flag telling whether this attribute is "advanced" (to be displayed under the advanced section).
       */
      private boolean advanced = false;

      /**
       * Gets the flag telling whether this attribute is "advanced" (to be displayed under the advanced section).
       *
       * @return the advanced
       */
      public boolean isAdvanced() {
        return this.advanced;
      }

      /**
       * Assigns the flag telling whether this attribute is "advanced" (to be displayed under the advanced section).
       *
       * @param advanced the advanced
       */
      public void setAdvanced(final boolean advanced) {
        this.advanced = advanced;
      }

      /**
       * Returns the message code for the attribute.
       *
       * @param eidasFlag is eIDAS used?
       * @return the message code to use for the attribute
       */
      public @NonNull String getMessageCode(final boolean eidasFlag) {
        return eidasFlag && StringUtils.hasText(this.messageCodeEidas) ? this.messageCodeEidas : this.messageCode;
      }

      /**
       * Returns the message code for the description field.
       *
       * @param eidasFlag is eIDAS used?
       * @return the message code for the description field
       */
      public @Nullable String getDescriptionMessageCode(final boolean eidasFlag) {
        return eidasFlag && StringUtils.hasText(this.descriptionMessageCodeEidas)
            ? this.descriptionMessageCodeEidas
            : this.descriptionMessageCode;
      }

      /** {@inheritDoc} */
      @Override
      public void afterPropertiesSet() {
        Assert.isTrue(StringUtils.hasText(this.attributeName) || StringUtils.hasText(this.claimName),
            "Invalid attribute - missing attribute-name or claim-name");
        Assert.hasText(this.messageCode, "Invalid attribute - missing message-code");
      }

      /** {@inheritDoc} */
      @Override
      public @NonNull String toString() {
        return "AttributeConfig(attributeName=" + this.attributeName + ", claimName=" + this.claimName
            + ", messageCode=" + this.messageCode + ", messageCodeEidas=" + this.messageCodeEidas
            + ", descriptionMessageCode=" + this.descriptionMessageCode + ", descriptionMessageCodeEidas="
            + this.descriptionMessageCodeEidas + ", advanced=" + this.advanced + ")";
      }
    }

  }

  /**
   * Configuration if Mutual TLS is used (needed for Holder-of-key functionality). Depending on the setup (whether AJP
   * is used or not), the header name or attribute name will be used.
   */
  public static class MutualTlsConfiguration implements InitializingBean {

    /**
     * Header name from where the mTls client certificate is read.
     */
    private @NonNull String headerName;

    /**
     * Gets the header name from where the mTls client certificate is read.
     *
     * @return the header name
     */
    public @NonNull String getHeaderName() {
      return this.headerName;
    }

    /**
     * Assigns the header name from where the mTls client certificate is read.
     *
     * @param headerName the header name
     */
    public void setHeaderName(final @NonNull String headerName) {
      this.headerName = headerName;
    }

    /**
     * Attribute name from where the mTls client certificate is read.
     */
    private @NonNull String attributeName;

    /**
     * Gets the attribute name from where the mTls client certificate is read.
     *
     * @return the attribute name
     */
    public @NonNull String getAttributeName() {
      return this.attributeName;
    }

    /**
     * Assigns the attribute name from where the mTls client certificate is read.
     *
     * @param attributeName the attribute name
     */
    public void setAttributeName(final @NonNull String attributeName) {
      this.attributeName = attributeName;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      if (!StringUtils.hasText(this.headerName)) {
        this.headerName = "SSL_CLIENT_CERT";
      }
      if (!StringUtils.hasText(this.attributeName)) {
        this.attributeName = "jakarta.servlet.request.X509Certificate";
      }
    }

  }

  /**
   * Discovery configuration, i.e., how to select which IdP to use.
   */
  public static class DiscoveryConfiguration implements InitializingBean {

    /**
     * The time we should keep an IdP list in the cache (in seconds).
     */
    private @NonNull Integer cacheTime;

    /**
     * Gets the time we should keep an IdP list in the cache (in seconds).
     *
     * @return the cache time
     */
    public @NonNull Integer getCacheTime() {
      return this.cacheTime;
    }

    /**
     * Assigns the time we should keep an IdP list in the cache (in seconds).
     *
     * @param cacheTime the cache time
     */
    public void setCacheTime(final @NonNull Integer cacheTime) {
      this.cacheTime = cacheTime;
    }

    /**
     * Setting that tells whether we should ignore contract entity categories when matching.
     */
    private boolean ignoreContracts = true;

    /**
     * Gets the setting that tells whether we should ignore contract entity categories when matching.
     *
     * @return the ignore contracts
     */
    public boolean isIgnoreContracts() {
      return this.ignoreContracts;
    }

    /**
     * Assigns the setting that tells whether we should ignore contract entity categories when matching.
     *
     * @param ignoreContracts the ignore contracts
     */
    public void setIgnoreContracts(final boolean ignoreContracts) {
      this.ignoreContracts = ignoreContracts;
    }

    /**
     * List of black listed IdPs.
     */
    private @Nullable List<String> blackList;

    /**
     * Gets the list of black listed IdPs.
     *
     * @return the list of black listed IdPs
     */
    public @Nullable List<String> getBlackList() {
      return this.blackList;
    }

    /**
     * Assigns the list of black listed IdPs.
     *
     * @param blackList the list of black listed IdPs
     */
    public void setBlackList(final @Nullable List<String> blackList) {
      this.blackList = blackList;
    }

    /**
     * Whether to only include the statically configured IdP:s (see {@code idp}).
     */
    private boolean includeOnlyStatic = false;

    /**
     * Tells whether to only include the statically configured IdP:s (see {@code idp}).
     *
     * @return the include only static
     */
    public boolean isIncludeOnlyStatic() {
      return this.includeOnlyStatic;
    }

    /**
     * Assigns whether to only include the statically configured IdP:s (see {@code idp}).
     *
     * @param includeOnlyStatic the include only static
     */
    public void setIncludeOnlyStatic(final boolean includeOnlyStatic) {
      this.includeOnlyStatic = includeOnlyStatic;
    }

    /**
     * Resource pointing at an YML-file containing static configured IdP:s.
     */
    private @Nullable Resource staticIdpConfiguration;

    /**
     * Gets the resource pointing at an YML-file containing static configured IdP:s.
     *
     * @return the static idp configuration
     */
    public @Nullable Resource getStaticIdpConfiguration() {
      return this.staticIdpConfiguration;
    }

    /**
     * Assigns the resource pointing at an YML-file containing static configured IdP:s.
     *
     * @param staticIdpConfiguration the static idp configuration
     */
    public void setStaticIdpConfiguration(final @Nullable Resource staticIdpConfiguration) {
      this.staticIdpConfiguration = staticIdpConfiguration;
    }

    /**
     * Statically configured IdP:s.
     */
    private @Nullable List<StaticIdpDiscoEntry> idp;

    /**
     * Gets the statically configured IdP:s.
     *
     * @return the statically configured IdP:s
     */
    public @Nullable List<StaticIdpDiscoEntry> getIdp() {
      return this.idp;
    }

    /**
     * Assigns the statically configured IdP:s.
     *
     * @param idp the statically configured IdP:s
     */
    public void setIdp(final @Nullable List<StaticIdpDiscoEntry> idp) {
      this.idp = idp;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      if (this.cacheTime == null) {
        this.cacheTime = 600;
      }
      if (this.idp != null) {
        for (final StaticIdpDiscoEntry e : this.idp) {
          e.afterPropertiesSet();
        }
      }
    }

  }

  /**
   * Configuration properties class for SP metadata.
   */
  public static class MetadataConfiguration implements InitializingBean {

    /**
     * The entity categories to include in the metadata extension.
     */
    private @Nullable List<String> entityCategories;

    /**
     * Gets the entity categories to include in the metadata extension.
     *
     * @return the entity categories to include in the metadata extension
     */
    public @Nullable List<String> getEntityCategories() {
      return this.entityCategories;
    }

    /**
     * Assigns the entity categories to include in the metadata extension.
     *
     * @param entityCategories the entity categories to include in the metadata extension
     */
    public void setEntityCategories(final @Nullable List<String> entityCategories) {
      this.entityCategories = entityCategories;
    }

    /**
     * Configuration for the UIInfo extension.
     */
    private @NonNull UIInfoConfig uiinfo;

    /**
     * Gets the configuration for the UIInfo extension.
     *
     * @return the configuration for the UIInfo extension
     */
    public @NonNull UIInfoConfig getUiinfo() {
      return this.uiinfo;
    }

    /**
     * Assigns the configuration for the UIInfo extension.
     *
     * @param uiinfo the configuration for the UIInfo extension
     */
    public void setUiinfo(final @NonNull UIInfoConfig uiinfo) {
      this.uiinfo = uiinfo;
    }

    /**
     * Configuration for the Organization element.
     */
    private @Nullable OrganizationConfig organization;

    /**
     * Gets the configuration for the Organization element.
     *
     * @return the configuration for the Organization element
     */
    public @Nullable OrganizationConfig getOrganization() {
      return this.organization;
    }

    /**
     * Assigns the configuration for the Organization element.
     *
     * @param organization the configuration for the Organization element
     */
    public void setOrganization(final @Nullable OrganizationConfig organization) {
      this.organization = organization;
    }

    /**
     * Configuration for the ContactPerson elements.
     */
    private @Nullable Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons;

    /**
     * Gets the configuration for the ContactPerson elements.
     *
     * @return the configuration for the ContactPerson elements
     */
    public @Nullable Map<ContactPersonTypeEnumeration, ContactPersonConfig> getContactPersons() {
      return this.contactPersons;
    }

    /**
     * Assigns the configuration for the ContactPerson elements.
     *
     * @param contactPersons the configuration for the ContactPerson elements
     */
    public void setContactPersons(
        final @Nullable Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons) {
      this.contactPersons = contactPersons;
    }

    /**
     * Requested attributes.
     */
    @Nullable List<RequestedAttributeConfig> requestedAttributes;

    /**
     * Gets the requested attributes.
     *
     * @return the requested attributes
     */
    public @Nullable List<RequestedAttributeConfig> getRequestedAttributes() {
      return this.requestedAttributes;
    }

    /**
     * Assigns the requested attributes.
     *
     * @param requestedAttributes the requested attributes
     */
    public void setRequestedAttributes(final @Nullable List<RequestedAttributeConfig> requestedAttributes) {
      this.requestedAttributes = requestedAttributes;
    }

    /**
     * Service names (for AttributeConsumingServiceBuilder).
     */
    @Nullable List<LocalizedString> serviceNames;

    /**
     * Gets the service names (for AttributeConsumingServiceBuilder).
     *
     * @return the service names (for AttributeConsumingServiceBuilder)
     */
    public @Nullable List<LocalizedString> getServiceNames() {
      return this.serviceNames;
    }

    /**
     * Assigns the service names (for AttributeConsumingServiceBuilder).
     *
     * @param serviceNames the service names (for AttributeConsumingServiceBuilder)
     */
    public void setServiceNames(final @Nullable List<LocalizedString> serviceNames) {
      this.serviceNames = serviceNames;
    }

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notNull(this.uiinfo, "sp.metadata.uiinfo must be set");
      this.uiinfo.afterPropertiesSet();
    }

    /**
     * Configuration class for UIInfo.
     */
    public static class UIInfoConfig implements InitializingBean {

      /**
       * The UIInfo display names. Given as country-code-text.
       */
      private @NonNull List<LocalizedString> displayNames;

      /**
       * Gets the UIInfo display names.
       *
       * @return the UIInfo display names
       */
      public @NonNull List<LocalizedString> getDisplayNames() {
        return this.displayNames;
      }

      /**
       * Assigns the UIInfo display names.
       *
       * @param displayNames the UIInfo display names
       */
      public void setDisplayNames(final @NonNull List<LocalizedString> displayNames) {
        this.displayNames = displayNames;
      }

      /**
       * The UIInfo descriptions. Given as country-code-text.
       */
      private @Nullable List<LocalizedString> descriptions;

      /**
       * Gets the UIInfo descriptions.
       *
       * @return the UIInfo descriptions
       */
      public @Nullable List<LocalizedString> getDescriptions() {
        return this.descriptions;
      }

      /**
       * Assigns the UIInfo descriptions.
       *
       * @param descriptions the UIInfo descriptions
       */
      public void setDescriptions(final @Nullable List<LocalizedString> descriptions) {
        this.descriptions = descriptions;
      }

      /**
       * The UIInfo logotypes.
       */
      private @NonNull List<UIInfoLogo> logos;

      /**
       * Gets the UIInfo logotypes.
       *
       * @return the UIInfo logotypes
       */
      public @NonNull List<UIInfoLogo> getLogos() {
        return this.logos;
      }

      /**
       * Assigns the UIInfo logotypes.
       *
       * @param logos the UIInfo logotypes
       */
      public void setLogos(final @NonNull List<UIInfoLogo> logos) {
        this.logos = logos;
      }

      /** {@inheritDoc} */
      @Override
      public void afterPropertiesSet() {
        Assert.notEmpty(this.displayNames, "sp.metadata.uiinfo.display-names must be set");
        Assert.isTrue(this.displayNames.stream().anyMatch(d -> "sv".equals(d.getLanguage())),
            "sp.metadata.uiinfo.display-names does not contain a Swedish display name");
        Assert.notEmpty(this.logos, "sp.metadata.uiinfo.logos must be set");
        for (final UIInfoLogo logo : this.logos) {
          logo.afterPropertiesSet();
        }
      }

      /**
       * Configuration class for the Logo element of the UIInfo element.
       */
      public static class UIInfoLogo implements InitializingBean {

        /**
         * The logotype path (minus baseUri and context-path).
         */
        private @NonNull String path;

        /**
         * Gets the logotype path (minus baseUri and context-path).
         *
         * @return the logotype path (minus baseUri and context-path)
         */
        public @NonNull String getPath() {
          return this.path;
        }

        /**
         * Assigns the logotype path (minus baseUri and context-path).
         *
         * @param path the logotype path (minus baseUri and context-path)
         */
        public void setPath(final @NonNull String path) {
          this.path = path;
        }

        /**
         * The logotype height (in pixels).
         */
        private @Nullable Integer height;

        /**
         * Gets the logotype height (in pixels).
         *
         * @return the logotype height (in pixels)
         */
        public @Nullable Integer getHeight() {
          return this.height;
        }

        /**
         * Assigns the logotype height (in pixels).
         *
         * @param height the logotype height (in pixels)
         */
        public void setHeight(final @Nullable Integer height) {
          this.height = height;
        }

        /**
         * The logotype width (in pixels).
         */
        private @Nullable Integer width;

        /**
         * Gets the logotype width (in pixels).
         *
         * @return the logotype width (in pixels)
         */
        public @Nullable Integer getWidth() {
          return this.width;
        }

        /**
         * Assigns the logotype width (in pixels).
         *
         * @param width the logotype width (in pixels)
         */
        public void setWidth(final @Nullable Integer width) {
          this.width = width;
        }

        /** {@inheritDoc} */
        @Override
        public void afterPropertiesSet() {
          Assert.hasText(this.path, "sp.metadata.uiinfo.logos[].path must be set");
        }

        /** {@inheritDoc} */
        @Override
        public @NonNull String toString() {
          return "UIInfoLogo(path=" + this.path + ", height=" + this.height + ", width=" + this.width + ")";
        }
      }

      /** {@inheritDoc} */
      @Override
      public @NonNull String toString() {
        return "UIInfoConfig(displayNames=" + this.displayNames + ", descriptions=" + this.descriptions + ", logos="
            + this.logos + ")";
      }
    }

    /**
     * Configuration class for the Organization element.
     */
    public static class OrganizationConfig {
      /**
       * The organization names. Given as country-code-text.
       */
      private @Nullable List<LocalizedString> names;

      /**
       * Gets the organization names.
       *
       * @return the organization names
       */
      public @Nullable List<LocalizedString> getNames() {
        return this.names;
      }

      /**
       * Assigns the organization names.
       *
       * @param names the organization names
       */
      public void setNames(final @Nullable List<LocalizedString> names) {
        this.names = names;
      }

      /**
       * The organization display names. Given as country-code-text.
       */
      private @Nullable List<LocalizedString> displayNames;

      /**
       * Gets the organization display names.
       *
       * @return the organization display names
       */
      public @Nullable List<LocalizedString> getDisplayNames() {
        return this.displayNames;
      }

      /**
       * Assigns the organization display names.
       *
       * @param displayNames the organization display names
       */
      public void setDisplayNames(final @Nullable List<LocalizedString> displayNames) {
        this.displayNames = displayNames;
      }

      /**
       * The organization URL:s.
       */
      private @Nullable List<LocalizedString> urls;

      /**
       * Gets the organization URL:s.
       *
       * @return the organization URL:s
       */
      public @Nullable List<LocalizedString> getUrls() {
        return this.urls;
      }

      /**
       * Assigns the organization URL:s.
       *
       * @param urls the organization URL:s
       */
      public void setUrls(final @Nullable List<LocalizedString> urls) {
        this.urls = urls;
      }

      /**
       * The (Swedish) organization number (no hyphens).
       */
      private @Nullable String number;

      /**
       * Gets the (Swedish) organization number (no hyphens).
       *
       * @return the (Swedish) organization number (no hyphens)
       */
      public @Nullable String getNumber() {
        return this.number;
      }

      /**
       * Assigns the (Swedish) organization number (no hyphens).
       *
       * @param number the (Swedish) organization number (no hyphens)
       */
      public void setNumber(final @Nullable String number) {
        this.number = number;
      }

      /** {@inheritDoc} */
      @Override
      public @NonNull String toString() {
        return "OrganizationConfig(names=" + this.names + ", displayNames=" + this.displayNames + ", urls=" + this.urls
            + ", number=" + this.number + ")";
      }
    }

    /**
     * Configuration class for the ContactPerson element.
     */
    public static class ContactPersonConfig {

      /**
       * The company.
       */
      private @Nullable String company;

      /**
       * Gets the company.
       *
       * @return the company
       */
      public @Nullable String getCompany() {
        return this.company;
      }

      /**
       * Assigns the company.
       *
       * @param company the company
       */
      public void setCompany(final @Nullable String company) {
        this.company = company;
      }

      /**
       * Given name.
       */
      private @Nullable String givenName;

      /**
       * Gets the given name.
       *
       * @return the given name
       */
      public @Nullable String getGivenName() {
        return this.givenName;
      }

      /**
       * Assigns the given name.
       *
       * @param givenName the given name
       */
      public void setGivenName(final @Nullable String givenName) {
        this.givenName = givenName;
      }

      /**
       * Surname.
       */
      private @Nullable String surname;

      /**
       * Gets the surname.
       *
       * @return the surname
       */
      public @Nullable String getSurname() {
        return this.surname;
      }

      /**
       * Assigns the surname.
       *
       * @param surname the surname
       */
      public void setSurname(final @Nullable String surname) {
        this.surname = surname;
      }

      /**
       * Email address.
       */
      private @Nullable String emailAddress;

      /**
       * Gets the email address.
       *
       * @return the email address
       */
      public @Nullable String getEmailAddress() {
        return this.emailAddress;
      }

      /**
       * Assigns the email address.
       *
       * @param emailAddress the email address
       */
      public void setEmailAddress(final @Nullable String emailAddress) {
        this.emailAddress = emailAddress;
      }

      /**
       * Telephone number.
       */
      private @Nullable String telephoneNumber;

      /**
       * Gets the telephone number.
       *
       * @return the telephone number
       */
      public @Nullable String getTelephoneNumber() {
        return this.telephoneNumber;
      }

      /**
       * Assigns the telephone number.
       *
       * @param telephoneNumber the telephone number
       */
      public void setTelephoneNumber(final @Nullable String telephoneNumber) {
        this.telephoneNumber = telephoneNumber;
      }

      /** {@inheritDoc} */
      @Override
      public @NonNull String toString() {
        return "ContactPersonConfig(company=" + this.company + ", givenName=" + this.givenName + ", surname="
            + this.surname + ", emailAddress=" + this.emailAddress + ", telephoneNumber=" + this.telephoneNumber + ")";
      }
    }

    /**
     * Configuration class for requested attributes.
     */
    public static class RequestedAttributeConfig {

      /**
       * The attribute name.
       */
      private @Nullable String name;

      /**
       * Gets the attribute name.
       *
       * @return the attribute name
       */
      public @Nullable String getName() {
        return this.name;
      }

      /**
       * Assigns the attribute name.
       *
       * @param name the attribute name
       */
      public void setName(final @Nullable String name) {
        this.name = name;
      }

      /**
       * Required?
       */
      private boolean required;

      /**
       * Gets the required? /.
       *
       * @return the required? /
       */
      public boolean isRequired() {
        return this.required;
      }

      /**
       * Assigns the required? /.
       *
       * @param required the required? /
       */
      public void setRequired(final boolean required) {
        this.required = required;
      }

      /** {@inheritDoc} */
      @Override
      public @NonNull String toString() {
        return "RequestedAttributeConfig(name=" + this.name + ", required=" + this.required + ")";
      }
    }

  }

}
