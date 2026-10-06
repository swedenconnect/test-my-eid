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

import net.shibboleth.shared.component.ComponentInitializationException;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.UsageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.OAEPparams;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.system.ApplicationTemp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.oidc.OpRegistry;
import se.swedenconnect.eid.sp.saml.IdpList;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;
import se.swedenconnect.eid.sp.saml.TestMyEidAuthnRequestGenerator;
import se.swedenconnect.eid.sp.utils.ClientCertificateGetter;
import se.swedenconnect.eid.sp.utils.FromHeaderClientCertificateGetter;
import se.swedenconnect.eid.sp.utils.FromRequestAttributeClientCertificateGetter;
import se.swedenconnect.eid.sp.utils.LogotypeInspector;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.replay.InMemoryReplayChecker;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SignMessageEncrypter;
import se.swedenconnect.opensaml.sweid.saml2.validation.SwedishEidResponseProcessorImpl;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Configuration for the Test SP.
 *
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Configuration
@EnableConfigurationProperties({ SpConfigurationProperties.class })
@DependsOn("openSAML")
public class SpConfiguration implements InitializingBean {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(SpConfiguration.class);

  /** For backwards compatibility. */
  @Value("${sign-sp.entity-id:#{null}}")
  private @Nullable String signSpEntityId;

  /** Temporary directory for caches. */
  private final ApplicationTemp tempDir = new ApplicationTemp();

  /** Algorithm requirements for encryption. */
  private List<EncryptionMethod> encryptionMethods;

  /** Configuration properties. */
  private final SpConfigurationProperties properties;

  /** The credential factory. */
  private final PkiCredentialFactory credentialFactory;

  /**
   * Constructor.
   *
   * @param properties the configuration properties
   * @param credentialFactory the credential factory
   */
  public SpConfiguration(final @NonNull SpConfigurationProperties properties,
      final @NonNull PkiCredentialFactory credentialFactory) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
  }

  /**
   * Assigns the sign service entityID given by the deprecated {@code sign-sp.entity-id} setting.
   *
   * @param signSpEntityId the entityID
   */
  public void setSignSpEntityId(final @Nullable String signSpEntityId) {
    this.signSpEntityId = signSpEntityId;
  }

  /**
   * Gets the {@code DebugFlag} bean telling whether we are running in debug mode.
   *
   * @return {@link Boolean}
   */
  @Bean("DebugFlag")
  @NonNull Boolean debugFlag() {
    return this.properties.isDebugMode() && StringUtils.hasText(this.properties.getDebugBaseUri());
  }

  /**
   * Gets the {@code hokActive} bean telling whether the Holder-of-key feature is enabled.
   *
   * @return {@link Boolean}
   */
  @Bean("hokActive")
  @NonNull Boolean hokActive() {
    return StringUtils.hasText(this.properties.getHokBaseUri())
        || StringUtils.hasText(this.properties.getDebugHokBaseUri());
  }

  /**
   * Returns the SP entityID bean.
   *
   * @return SP entityID
   */
  @Bean(name = "spEntityID")
  @NonNull EntityID spEntityID() {
    return new EntityID(this.properties.getEntityId());
  }

  /**
   * Returns the sign service entityID bean.
   *
   * @return sign service entityID
   */
  @Bean(name = "signSpEntityID")
  @NonNull EntityID signSpEntityID() {
    if (StringUtils.hasText(this.properties.getSignEntityId())) {
      return new EntityID(this.properties.getSignEntityId());
    }
    else if (StringUtils.hasText(this.signSpEntityId)) {
      log.warn("Use sp.sign-entity-id instead of sign-sp.entity-id");
      return new EntityID(this.signSpEntityId);
    }
    throw new BeanCreationException("Missing sp.sign-entity-id");
  }

  /**
   * Returns the entityID bean for the eIDAS connector.
   *
   * @return the eIDAS connector entityID
   */
  @Bean(name = "eidasConnectorEntityID")
  @NonNull EntityID eidasConnectorEntityID() {
    return new EntityID(this.properties.getEidasConnector().getEntityId());
  }

  /**
   * Returns the SP signing credential.
   *
   * @return the signing credential
   * @throws Exception for errors creating the credential
   */
  @Bean("signCredential")
  @NonNull X509Credential signCredential() throws Exception {
    return new OpenSamlCredential(this.credentialFactory.createCredential(this.properties.getCredential().getSign()));
  }

  /**
   * Returns the SP decryption credential.
   *
   * @return the decryption credential
   * @throws Exception for errors creating the credential
   */
  @Bean("encryptCredential")
  @NonNull X509Credential encryptCredential() throws Exception {
    return new OpenSamlCredential(
        this.credentialFactory.createCredential(this.properties.getCredential().getDecrypt()));
  }

  /**
   * Returns the credential used to sign SP metadata. Falls back to the signing credential if not configured.
   *
   * @return the metadata signing credential
   * @throws Exception for errors creating the credential
   */
  @Bean("mdSignCredential")
  @NonNull X509Credential mdSignCredential() throws Exception {
    if (this.properties.getCredential().getMdSign() != null) {
      return new OpenSamlCredential(
          this.credentialFactory.createCredential(this.properties.getCredential().getMdSign()));
    }
    else {
      return this.signCredential();
    }
  }

  /**
   * Returns the selectable UI languages.
   *
   * @return a list of UI languages
   */
  @Bean
  @NonNull List<UiLanguage> languages() {
    return this.properties.getUi().getLang();
  }

  /**
   * Returns the registry for displaying attribute information.
   *
   * @return an {@link AttributeInfoRegistry}
   */
  @Bean
  @NonNull AttributeInfoRegistry attributeInfoRegistry() {
    return new AttributeInfoRegistry(this.properties.getUi().getAttributes());
  }

  /**
   * Returns a client certificate getter that reads the certificate from a request attribute (AJP).
   *
   * @return a {@link ClientCertificateGetter}
   */
  @Bean
  @ConditionalOnProperty(name = "tomcat.ajp.enabled", havingValue = "true")
  @NonNull ClientCertificateGetter attributeBasedClientCertificateGetter() {
    return new FromRequestAttributeClientCertificateGetter(this.properties.getMtls().getAttributeName());
  }

  /**
   * Returns a client certificate getter that reads the certificate from a request header.
   *
   * @return a {@link ClientCertificateGetter}
   */
  @Bean
  @Profile("!local")
  @ConditionalOnProperty(name = "tomcat.ajp.enabled", matchIfMissing = true, havingValue = "false")
  @NonNull ClientCertificateGetter headerBasedClientCertificateGetter() {
    return new FromHeaderClientCertificateGetter(this.properties.getMtls().getHeaderName());
  }

  /**
   * Returns a client certificate getter that reads the certificate from a request attribute (local profile).
   *
   * @return a {@link ClientCertificateGetter}
   */
  @Bean
  @Profile("local")
  @NonNull ClientCertificateGetter attributeBasedClientCertificateGetter2() {
    return new FromRequestAttributeClientCertificateGetter(this.properties.getMtls().getAttributeName());
  }

  /**
   * Returns the user message templates, mapped by language tag.
   *
   * @return a map of language tags and user message templates
   * @throws IOException for errors reading the templates
   */
  @Bean("userMessages")
  @NonNull Map<String, String> userMessages() throws IOException {
    final Map<String, String> userMessages = new HashMap<>();
    for (final Map.Entry<String, Resource> entry : this.properties.getUi().getUserMessageTemplate().entrySet()) {

      try (final InputStream stream = entry.getValue().getInputStream()) {
        userMessages.put(entry.getKey(), new String(stream.readAllBytes(), StandardCharsets.UTF_8));
      }
    }
    return userMessages;
  }

  /**
   * Returns the IdP list used for discovery.
   *
   * @param metadataProvider the federation metadata provider
   * @param staticIdps statically configured IdP:s from a separate file
   * @param spMetadata the SP metadata
   * @param hokActive whether Holder-of-key is active
   * @param opRegistry the registry of OpenID Providers
   * @return an {@link IdpList}
   */
  @Bean
  @NonNull IdpList idpList(final @NonNull MetadataProvider metadataProvider,
      @Qualifier("staticIdps") final @NonNull List<StaticIdpDiscoEntry> staticIdps,
      @Qualifier("spMetadata") final @NonNull EntityDescriptor spMetadata,
      @Qualifier("hokActive") final @NonNull Boolean hokActive,
      final @NonNull OpRegistry opRegistry) {

    // Merge static IdP:s from configuration and those supplied in separate file
    //
    final List<StaticIdpDiscoEntry> idps = new ArrayList<>(
        Optional.ofNullable(this.properties.getDiscovery().getIdp())
            .orElseGet(Collections::emptyList));
    staticIdps.stream()
        .filter(i -> idps.stream()
            .noneMatch(i2 -> i2.getProtocol() == i.getProtocol() && Objects.equals(i2.getKey(), i.getKey())))
        .forEach(idps::add);

    final IdpList idpList = new IdpList(metadataProvider, spMetadata, idps,
        this.properties.getDiscovery().getBlackList(),
        this.properties.getDiscovery().isIncludeOnlyStatic(),
        hokActive, opRegistry);

    idpList.setCacheTime(this.properties.getDiscovery().getCacheTime());
    idpList.setIgnoreContracts(this.properties.getDiscovery().isIgnoreContracts());

    return idpList;
  }

  /**
   * Returns the bean that checks whether logotypes need a dark background.
   *
   * @return a {@link LogotypeInspector}
   */
  @Bean
  @NonNull LogotypeInspector logotypeInspector() {
    return new LogotypeInspector(this.properties.getDiscovery().getCacheTime());
  }

  /**
   * Returns the SAML response processor.
   *
   * @param metadataProvider the federation metadata provider
   * @param encryptCredential the decryption credential
   * @return a {@link ResponseProcessor}
   */
  @Bean(initMethod = "initialize")
  @NonNull ResponseProcessor responseProcessor(final @NonNull MetadataProvider metadataProvider,
      @Qualifier("encryptCredential") final @NonNull X509Credential encryptCredential) {

    final SwedishEidResponseProcessorImpl responseProcessor = new SwedishEidResponseProcessorImpl();
    responseProcessor.setMetadataResolver(metadataProvider.getMetadataResolver());
    responseProcessor.setDecrypter(new SAMLObjectDecrypter(encryptCredential));
    responseProcessor.setMessageReplayChecker(new InMemoryReplayChecker());
    return responseProcessor;
  }

  /**
   * Returns the federation metadata provider.
   *
   * @return a {@link MetadataProvider}
   * @throws Exception for setup errors
   */
  @Bean(initMethod = "initialize")
  @NonNull MetadataProvider metadataProvider() throws Exception {

    final X509Certificate cert = this.properties.getFederation().getMetadata().getValidationCertificate() != null
        ? (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
        this.properties.getFederation().getMetadata().getValidationCertificate().getInputStream())
        : null;

    final Resource location = this.properties.getFederation().getMetadata().getUrl();
    final AbstractMetadataProvider provider;
    if (location instanceof final UrlResource urlResource && !urlResource.isFile()) {

      final File backupFile = new File(this.tempDir.getDir(), "metadata-cache.xml");

      provider = new HTTPMetadataProvider(location.getURL().toString(),
          backupFile.getAbsolutePath(),
          HTTPMetadataProvider.createDefaultHttpClient(null /* trust all */, new NoopHostnameVerifier()));

      if (cert != null) {
        provider.setSignatureVerificationCertificate(cert);
      }
      else {
        log.warn("No validation certificate assigned for metadata source {} "
            + "- downloaded metadata can not be trusted", location.getURL());
      }
    }
    else if (location instanceof FileSystemResource) {
      provider = new FilesystemMetadataProvider(location.getFile());
      if (cert != null) {
        provider.setSignatureVerificationCertificate(cert);
      }
    }
    else {
      final Document doc =
          XMLObjectProviderRegistrySupport.getParserPool().parse(location.getInputStream());
      provider = new StaticMetadataProvider(doc.getDocumentElement());
    }
    provider.setPerformSchemaValidation(false);

    return provider;
  }

  /**
   * Builds the SP metadata.
   *
   * @param contextPath the servlet context path
   * @param serverPort the server port
   * @param signCredential the signing credential
   * @param encryptCredential the decryption credential
   * @return an {@link EntityDescriptor}
   */
  @Bean("spMetadata")
  @NonNull EntityDescriptor spMetadata(
      @Value("${server.servlet.context-path}") final @NonNull String contextPath,
      @Value("${server.port}") final int serverPort,
      @Qualifier("signCredential") final @NonNull X509Credential signCredential,
      @Qualifier("encryptCredential") final @NonNull X509Credential encryptCredential) {

    final List<AssertionConsumerService> acs = new ArrayList<>();
    int index = 0;
    acs.add(AssertionConsumerServiceBuilder.builder()
        .binding(SAMLConstants.SAML2_POST_BINDING_URI)
        .location(
            String.format("%s%s/saml2/post", this.properties.getBaseUri(), contextPath.equals("/") ? "" : contextPath))
        .index(index++)
        .isDefault(true)
        .build());

    if (StringUtils.hasText(this.properties.getDebugBaseUri())) {
      acs.add(AssertionConsumerServiceBuilder.builder()
          .binding(SAMLConstants.SAML2_POST_BINDING_URI)
          .location(
              String.format("%s%s/saml2/post", this.properties.getDebugBaseUri().trim(),
                  contextPath.equals("/") ? "" : contextPath))
          .index(index++)
          .isDefault(false)
          .build());
    }
    if (StringUtils.hasText(this.properties.getHokBaseUri())) {
      acs.add(AssertionConsumerServiceBuilder.builder()
          .hokPostBinding()
          .location(String.format("%s%s/saml2/hok", this.properties.getHokBaseUri().trim(),
              contextPath.equals("/") ? "" : contextPath))
          .index(index++)
          .isDefault(false)
          .build());
    }
    if (StringUtils.hasText(this.properties.getDebugHokBaseUri())) {
      acs.add(AssertionConsumerServiceBuilder.builder()
          .hokPostBinding()
          .location(
              String.format("%s%s/saml2/hok", this.properties.getDebugHokBaseUri().trim(),
                  contextPath.equals("/") ? "" : contextPath))
          .index(index++)
          .isDefault(false)
          .build());
    }

    return EntityDescriptorBuilder.builder()
        .entityID(this.spEntityID().getEntityID())
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(this.properties.getMetadata().getEntityCategories())
                .build())
            .build())
        .ssoDescriptor(SPSSODescriptorBuilder.builder()
            .authnRequestsSigned(true)
            .wantAssertionsSigned(false)
            .extensions(ExtensionsBuilder.builder()
                .extension(MetadataUtils.getUIInfoElement(
                    this.properties.getMetadata().getUiinfo(), this.properties.getBaseUri(), contextPath))
                .build())
            .keyDescriptors(
                KeyDescriptorBuilder.builder()
                    .use(UsageType.SIGNING)
                    .keyName("Signing")
                    .certificate(signCredential.getEntityCertificate())
                    .build(),
                KeyDescriptorBuilder.builder()
                    .use(UsageType.ENCRYPTION)
                    .keyName("Encryption")
                    .certificate(encryptCredential.getEntityCertificate())
                    .encryptionMethodsExt(this.encryptionMethods)
                    .build())
            .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
            .attributeConsumingServices(MetadataUtils.getAttributeConsumingService(
                this.properties.getMetadata().getServiceNames(),
                this.properties.getMetadata().getRequestedAttributes()))
            .assertionConsumerServices(acs)
            .build())
        .organization(MetadataUtils.getOrganizationElement(this.properties.getMetadata().getOrganization()))
        .contactPersons(MetadataUtils.getContactPersonElements(this.properties.getMetadata().getContactPersons()))
        .build();
  }

  /**
   * Returns the container for signing and publishing the SP metadata.
   *
   * @param spMetadata the SP metadata
   * @param mdSignCredential the metadata signing credential
   * @return an {@link EntityDescriptorContainer}
   */
  @Bean("spEntityDescriptorContainer")
  @NonNull EntityDescriptorContainer entityDescriptorContainer(
      @Qualifier("spMetadata") final @NonNull EntityDescriptor spMetadata,
      @Qualifier("mdSignCredential") final @NonNull X509Credential mdSignCredential) {
    return new EntityDescriptorContainer(spMetadata, mdSignCredential);
  }

  /**
   * Builds the metadata for the signature service SP.
   *
   * @param contextPath the servlet context path
   * @param serverPort the server port
   * @param signCredential the signing credential
   * @param encryptCredential the decryption credential
   * @return an {@link EntityDescriptor}
   */
  @Bean("signSpMetadata")
  @NonNull EntityDescriptor signSpMetadata(
      @Value("${server.servlet.context-path}") final @NonNull String contextPath,
      @Value("${server.port}") final int serverPort,
      @Qualifier("signCredential") final @NonNull X509Credential signCredential,
      @Qualifier("encryptCredential") final @NonNull X509Credential encryptCredential) {

    final List<AssertionConsumerService> acs = new ArrayList<>();
    int index = 0;
    acs.add(AssertionConsumerServiceBuilder.builder()
        .binding(SAMLConstants.SAML2_POST_BINDING_URI)
        .location(
            String.format("%s%s/saml2/sign", this.properties.getBaseUri(), contextPath.equals("/") ? "" : contextPath))
        .index(index++)
        .isDefault(true)
        .build());

    if (StringUtils.hasText(this.properties.getDebugBaseUri())) {
      acs.add(AssertionConsumerServiceBuilder.builder()
          .binding(SAMLConstants.SAML2_POST_BINDING_URI)
          .location(
              String.format("%s%s/saml2/sign", this.properties.getDebugBaseUri().trim(),
                  contextPath.equals("/") ? "" : contextPath))
          .index(index++)
          .isDefault(false)
          .build());
    }
    if (StringUtils.hasText(this.properties.getHokBaseUri())) {
      acs.add(AssertionConsumerServiceBuilder.builder()
          .hokPostBinding()
          .location(
              String.format("%s%s/saml2/signhok", this.properties.getHokBaseUri().trim(),
                  contextPath.equals("/") ? "" : contextPath))
          .index(index++)
          .isDefault(false)
          .build());
    }
    if (StringUtils.hasText(this.properties.getDebugHokBaseUri())) {
      acs.add(AssertionConsumerServiceBuilder.builder()
          .hokPostBinding()
          .location(String.format("%s%s/saml2/signhok", this.properties.getDebugHokBaseUri().trim(),
              contextPath.equals("/") ? "" : contextPath))
          .index(index++)
          .isDefault(false)
          .build());
    }

    final List<String> entityCategories = new ArrayList<>();
    entityCategories.add(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri());
    entityCategories.addAll(Optional.ofNullable(this.properties.getMetadata().getEntityCategories())
        .orElse(Collections.emptyList()));

    return EntityDescriptorBuilder.builder()
        .entityID(this.signSpEntityID().getEntityID())
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(entityCategories)
                .build())
            .build())
        .ssoDescriptor(SPSSODescriptorBuilder.builder()
            .authnRequestsSigned(true)
            .wantAssertionsSigned(true)
            .extensions(ExtensionsBuilder.builder()
                .extension(MetadataUtils.getUIInfoElement(
                    this.properties.getMetadata().getUiinfo(),
                    this.properties.getBaseUri(), contextPath))
                .build())
            .keyDescriptors(
                KeyDescriptorBuilder.builder()
                    .use(UsageType.SIGNING)
                    .keyName("Signing")
                    .certificate(signCredential.getEntityCertificate())
                    .build(),
                KeyDescriptorBuilder.builder()
                    .use(UsageType.ENCRYPTION)
                    .keyName("Encryption")
                    .certificate(encryptCredential.getEntityCertificate())
                    .encryptionMethodsExt(this.encryptionMethods)
                    .build())
            .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
            .attributeConsumingServices(MetadataUtils.getAttributeConsumingService(
                this.properties.getMetadata().getServiceNames(),
                this.properties.getMetadata().getRequestedAttributes()))
            .assertionConsumerServices(acs)
            .build())
        .organization(MetadataUtils.getOrganizationElement(this.properties.getMetadata().getOrganization()))
        .contactPersons(MetadataUtils.getContactPersonElements(this.properties.getMetadata().getContactPersons()))
        .build();
  }

  /**
   * Returns the container for signing and publishing the signature service SP metadata.
   *
   * @param signSpMetadata the signature service SP metadata
   * @param mdSignCredential the metadata signing credential
   * @return an {@link EntityDescriptorContainer}
   */
  @Bean("signSpEntityDescriptorContainer")
  @NonNull EntityDescriptorContainer signSpEntityDescriptorContainer(
      @Qualifier("signSpMetadata") final @NonNull EntityDescriptor signSpMetadata,
      @Qualifier("mdSignCredential") final @NonNull X509Credential mdSignCredential) {
    return new EntityDescriptorContainer(signSpMetadata, mdSignCredential);
  }

  /**
   * Returns the AuthnRequest generator for the SP.
   *
   * @param metadata the SP metadata
   * @param signCredential the signing credential
   * @param metadataProvider the federation metadata provider
   * @return a {@link TestMyEidAuthnRequestGenerator}
   */
  @Bean(name = "spAuthnRequestGenerator", initMethod = "initialize")
  @NonNull TestMyEidAuthnRequestGenerator spAuthnRequestGenerator(
      @Qualifier("spMetadata") final @NonNull EntityDescriptor metadata,
      @Qualifier("signCredential") final @NonNull X509Credential signCredential,
      final @NonNull MetadataProvider metadataProvider) {

    return new TestMyEidAuthnRequestGenerator(metadata, signCredential, metadataProvider.getMetadataResolver());
  }

  /**
   * Returns the AuthnRequest generator for the signature service SP.
   *
   * @param metadata the signature service SP metadata
   * @param signCredential the signing credential
   * @param metadataProvider the federation metadata provider
   * @param signMessageEncrypter for encrypting sign messages
   * @return a {@link TestMyEidAuthnRequestGenerator}
   */
  @Bean(name = "signSpAuthnRequestGenerator", initMethod = "initialize")
  @NonNull TestMyEidAuthnRequestGenerator signSpAuthnRequestGenerator(
      @Qualifier("signSpMetadata") final @NonNull EntityDescriptor metadata,
      @Qualifier("signCredential") final @NonNull X509Credential signCredential,
      final @NonNull MetadataProvider metadataProvider,
      final @NonNull SignMessageEncrypter signMessageEncrypter) {

    final TestMyEidAuthnRequestGenerator generator =
        new TestMyEidAuthnRequestGenerator(metadata, signCredential, metadataProvider.getMetadataResolver());
    generator.setSignMessageEncrypter(signMessageEncrypter);
    return generator;
  }

  /**
   * Returns the encrypter for sign messages.
   *
   * @param metadataProvider the federation metadata provider
   * @return a {@link SignMessageEncrypter}
   * @throws ComponentInitializationException for initialization errors
   */
  @Bean
  @NonNull SignMessageEncrypter signMessageEncrypter(final @NonNull MetadataProvider metadataProvider)
      throws ComponentInitializationException {
    return new SignMessageEncrypter(new SAMLObjectEncrypter(metadataProvider.getMetadataResolver()));
  }

  /**
   * Based on the configured data and key transport algorithms we set up the algorithm requirements for inclusion in SP
   * metadata.
   */
  @Override
  public void afterPropertiesSet() throws Exception {
    this.encryptionMethods = new ArrayList<>();

    final EncryptionConfiguration encryptionConfig = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();

    final List<String> keyTransportMethods = encryptionConfig.getKeyTransportEncryptionAlgorithms();
    for (final String algo : keyTransportMethods) {
      final AlgorithmDescriptor algoDesc = AlgorithmSupport.getGlobalAlgorithmRegistry().get(algo);
      if (algoDesc == null) {
        continue;
      }

      final X509Credential encryptCredential = new OpenSamlCredential(
          this.credentialFactory.createCredential(this.properties.getCredential().getDecrypt()));

      if (AlgorithmDescriptor.AlgorithmType.KeyTransport == algoDesc.getType()
          && AlgorithmSupport.credentialSupportsAlgorithmForEncryption(encryptCredential, algoDesc)) {
        final EncryptionMethod method =
            (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
        method.setAlgorithm(algo);
        if (AlgorithmSupport.isRSAOAEP(algo)) {
          final RSAOAEPParameters pars = encryptionConfig.getRSAOAEPParameters();
          if (pars != null) {
            if (pars.getDigestMethod() != null) {
              final DigestMethod dm = (DigestMethod) XMLObjectSupport.buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
              dm.setAlgorithm(pars.getDigestMethod());
              method.getUnknownXMLObjects().add(dm);
            }
            if (pars.getOAEPParams() != null) {
              final OAEPparams oaepParams =
                  (OAEPparams) XMLObjectSupport.buildXMLObject(OAEPparams.DEFAULT_ELEMENT_NAME);
              oaepParams.setValue(pars.getOAEPParams());
              method.setOAEPparams(oaepParams);
            }
          }
        }

        this.encryptionMethods.add(method);
      }
    }

    for (final String algo : encryptionConfig.getDataEncryptionAlgorithms()) {
      if (algo.equals(EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES)) {
        continue;
      }
      final EncryptionMethod method =
          (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
      method.setAlgorithm(algo);
      this.encryptionMethods.add(method);
    }
  }

}
