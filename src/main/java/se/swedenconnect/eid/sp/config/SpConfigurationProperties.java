/*
 * Copyright 2018-2024 Sweden Connect
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

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

import java.util.List;
import java.util.Map;

/**
 * Configuration properties for the SP.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("sp")
@Slf4j
public class SpConfigurationProperties implements InitializingBean {

  /**
   * The Base URI for the deployed application.
   */
  @Getter
  @Setter
  private String baseUri;

  /**
   * Base URI for holder of key profile. Must be set if HoK is enabled.
   */
  @Getter
  @Setter
  private String hokBaseUri;

  /**
   * Optional. The Base URI when debugging.
   */
  @Getter
  @Setter
  private String debugBaseUri;

  /**
   * Base URI for holder of key profile in debug mode.
   */
  @Getter
  @Setter
  private String debugHokBaseUri;

  /**
   * The SAML entity ID for the application.
   */
  @Getter
  @Setter
  private String entityId;

  /**
   * The SAML entity ID for when the application mimics a Signature Service.
   */
  @Getter
  @Setter
  private String signEntityId;

  /**
   * The path used during "signing". Only configurable so that the Test my Signature can extend this app.
   */
  @Getter
  @Setter
  private String signPath;

  /**
   * Whether we are in local debug mode.
   */
  @Getter
  @Setter
  private boolean debugMode = false;

  /**
   * eIDAS connector configuration.
   */
  @NestedConfigurationProperty
  @Getter
  private EidasConnectorConfiguration eidasConnector = new EidasConnectorConfiguration();

  /**
   * SP credential configuration.
   */
  @NestedConfigurationProperty
  @Getter
  private CredentialsConfiguration credential = new CredentialsConfiguration();

  /**
   * Federation configuration.
   */
  @NestedConfigurationProperty
  @Getter
  private FederationConfiguration federation = new FederationConfiguration();

  /**
   * Configuration for selecting IdP to use.
   */
  @NestedConfigurationProperty
  @Getter
  private DiscoveryConfiguration discovery = new DiscoveryConfiguration();

  /**
   * Configuration for mutual TLS (needed for Holder-of-key).
   */
  @NestedConfigurationProperty
  @Getter
  private MutualTlsConfiguration mtls = new MutualTlsConfiguration();

  /**
   * UI configuration.
   */
  @NestedConfigurationProperty
  @Getter
  private UiConfiguration ui = new UiConfiguration();

  /**
   * SAML metadata.
   */
  @NestedConfigurationProperty
  @Getter
  private MetadataConfiguration metadata = new MetadataConfiguration();

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
    @Getter
    @Setter
    private String entityId;

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
    @Getter
    @Setter
    private PkiCredentialConfiguration sign;

    /**
     * The SP decryption (encryption) credentials.
     */
    @Getter
    @Setter
    private PkiCredentialConfiguration decrypt;

    /**
     * The SP metadata signing credentials.
     */
    @Getter
    @Setter
    private PkiCredentialConfiguration mdSign;

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

      private PkiCredentialFactoryBean factory;

      /**
       * See {@link PkiCredentialConfigurationProperties#setResource(Resource)}.
       *
       * @param resource the file resource pointing at the JKS/P12
       */
      public void setFile(final Resource resource) {
        this.setResource(resource);
      }

      public PkiCredential createCredential() throws Exception {
        if (this.factory == null) {
          this.factory = new PkiCredentialFactoryBean(this);
          this.factory.afterPropertiesSet();
        }
        return this.factory.getObject();
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
    @Getter
    @Setter
    private Metadata metadata;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notNull(this.metadata, "sp.federation.metadata must be assigned");
      Assert.notNull(this.metadata.getUrl(), "sp.federation.metadata.url must be assigned");
      if (this.metadata.getValidationCertificate() == null) {
        log.warn("sp.federation.metadata.validation-certificate is not assigned");
      }
    }

    public static class Metadata {

      /**
       * URL/resource for downloading metadata.
       */
      @Getter
      @Setter
      private Resource url;

      /**
       * Resource pointing at the metadata validation certificate.
       */
      @Getter
      @Setter
      private Resource validationCertificate;

    }

  }

  /**
   * Configuration for the application UI.
   */
  public static class UiConfiguration implements InitializingBean {

    /**
     * UI languages.
     */
    @Getter
    @Setter
    private List<UiLanguage> lang;

    /**
     * Templates to user messages for different languages.
     */
    @Getter
    @Setter
    private Map<String, Resource> userMessageTemplate;

    /**
     * Attribute info (for viewing info about received SAML attributes).
     */
    @Getter
    @Setter
    private List<AttributeConfig> attributes;

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
    @Data
    @ToString
    public static class AttributeConfig implements InitializingBean {

      /**
       * The name of the attribute.
       */
      private String attributeName;

      /**
       * The message code for the attribute.
       */
      private String messageCode;

      /**
       * The message code the attribute if eIDAS is used. If {@code null}, the value for {@code messageCode} is used.
       */
      private String messageCodeEidas;

      /**
       * The message code for the attribute description.
       */
      private String descriptionMessageCode;

      /**
       * The message code the for attribute description in eIDAS context.
       */
      private String descriptionMessageCodeEidas;

      /**
       * Flag telling whether this attribute is "advanced" (to be displayed under the advanced section).
       */
      private boolean advanced = false;

      /**
       * Returns the message code for the attribute.
       *
       * @param eidasFlag is eIDAS used?
       * @return the message code to use for the attribute
       */
      public String getMessageCode(final boolean eidasFlag) {
        return eidasFlag && StringUtils.hasText(this.messageCodeEidas) ? this.messageCodeEidas : this.messageCode;
      }

      /**
       * Returns the message code for the description field.
       *
       * @param eidasFlag is eIDAS used?
       * @return the message code for the description field
       */
      public String getDescriptionMessageCode(final boolean eidasFlag) {
        return eidasFlag && StringUtils.hasText(this.descriptionMessageCodeEidas)
            ? this.descriptionMessageCodeEidas
            : this.descriptionMessageCode;
      }

      /** {@inheritDoc} */
      @Override
      public void afterPropertiesSet() {
        Assert.hasText(this.attributeName, "Invalid attribute - missing attribute-name");
        Assert.hasText(this.messageCode, "Invalid attribute - missing message-code");
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
    @Getter
    @Setter
    private String headerName;

    /**
     * Attribute name from where the mTls client certificate is read.
     */
    @Getter
    @Setter
    private String attributeName;

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
    @Getter
    @Setter
    private Integer cacheTime;

    /**
     * Setting that tells whether we should ignore contract entity categories when matching.
     */
    @Getter
    @Setter
    private boolean ignoreContracts = true;

    /**
     * List of black listed IdPs.
     */
    @Getter
    @Setter
    private List<String> blackList;

    /**
     * Whether to only include the statically configured IdP:s (see {@code idp}).
     */
    @Getter
    @Setter
    private boolean includeOnlyStatic = false;

    /**
     * Resource pointing at an YML-file containing static configured IdP:s.
     */
    @Getter
    @Setter
    private Resource staticIdpConfiguration;

    /**
     * Statically configured IdP:s.
     */
    @Getter
    @Setter
    private List<StaticIdpDiscoEntry> idp;

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
    @Getter
    @Setter
    private List<String> entityCategories;

    /**
     * Configuration for the UIInfo extension.
     */
    @Getter
    @Setter
    private UIInfoConfig uiinfo;

    /**
     * Configuration for the Organization element.
     */
    @Getter
    @Setter
    private OrganizationConfig organization;

    /**
     * Configuration for the ContactPerson elements.
     */
    @Getter
    @Setter
    private Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons;

    /**
     * Requested attributes.
     */
    @Getter
    @Setter
    List<RequestedAttributeConfig> requestedAttributes;

    /**
     * Service names (for AttributeConsumingServiceBuilder).
     */
    @Getter
    @Setter
    List<LocalizedString> serviceNames;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notNull(this.uiinfo, "sp.metadata.uiinfo must be set");
      this.uiinfo.afterPropertiesSet();
    }

    /**
     * Configuration class for UIInfo.
     */
    @Data
    public static class UIInfoConfig implements InitializingBean {

      /**
       * The UIInfo display names. Given as country-code-text.
       */
      private List<LocalizedString> displayNames;

      /**
       * The UIInfo descriptions. Given as country-code-text.
       */
      private List<LocalizedString> descriptions;

      /**
       * The UIInfo logotypes.
       */
      private List<UIInfoLogo> logos;

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
      @Data
      public static class UIInfoLogo implements InitializingBean {

        /**
         * The logotype path (minus baseUri and context-path).
         */
        private String path;

        /**
         * The logotype height (in pixels).
         */
        private Integer height;

        /**
         * The logotype width (in pixels).
         */
        private Integer width;

        /** {@inheritDoc} */
        @Override
        public void afterPropertiesSet() {
          Assert.hasText(this.path, "sp.metadata.uiinfo.logos[].path must be set");
        }

      }

    }

    /**
     * Configuration class for the Organization element.
     */
    @Data
    public static class OrganizationConfig {
      /**
       * The organization names. Given as country-code-text.
       */
      private List<LocalizedString> names;

      /**
       * The organization display names. Given as country-code-text.
       */
      private List<LocalizedString> displayNames;

      /**
       * The organization URL:s.
       */
      private List<LocalizedString> urls;
    }

    /**
     * Configuration class for the ContactPerson element.
     */
    @Data
    public static class ContactPersonConfig {

      /**
       * The company.
       */
      private String company;

      /**
       * Given name.
       */
      private String givenName;

      /**
       * Surname.
       */
      private String surname;

      /**
       * Email address.
       */
      private String emailAddress;

      /**
       * Telephone number.
       */
      private String telephoneNumber;
    }

    /**
     * Configuration class for requested attributes.
     */
    @Data
    public static class RequestedAttributeConfig {

      /**
       * The attribute name.
       */
      private String name;

      /**
       * Required?
       */
      private boolean required;

    }

  }

}
