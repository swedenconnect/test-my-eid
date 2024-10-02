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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.micrometer.core.instrument.util.IOUtils;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.UsageType;
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
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.saml.IdpList;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;
import se.swedenconnect.eid.sp.saml.TestMyEidAuthnRequestGenerator;
import se.swedenconnect.eid.sp.utils.ClientCertificateGetter;
import se.swedenconnect.eid.sp.utils.FromHeaderClientCertificateGetter;
import se.swedenconnect.eid.sp.utils.FromRequestAttributeClientCertificateGetter;
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
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/**
 * Configuration for the Test SP.
 *
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Configuration
@EnableConfigurationProperties({ SpConfigurationProperties.class })
@DependsOn("openSAML")
@Slf4j
public class SpConfiguration implements InitializingBean {

  /** For backwards compatibility. */
  @Setter
  @Value("${sign-sp.entity-id:#{null}}")
  private String signSpEntityId;

  /** Temporary directory for caches. */
  private final ApplicationTemp tempDir = new ApplicationTemp();

  /** Algorithm requirements for encryption. */
  private List<EncryptionMethod> encryptionMethods;

  /** Configuration properties. */
  private final SpConfigurationProperties properties;

  /**
   * Constructor.
   *
   * @param properties the configuration properties
   */
  public SpConfiguration(final SpConfigurationProperties properties) {
    this.properties = properties;
  }

  /**
   * Gets the {@code DebugFlag} bean telling whether we are running in debug mode.
   *
   * @return {@link Boolean}
   */
  @Bean("DebugFlag")
  Boolean debugFlag() {
    return this.properties.isDebugMode() && StringUtils.hasText(this.properties.getDebugBaseUri());
  }

  /**
   * Gets the {@code hokActive} bean telling whether the Holder-of-key feature is enabled.
   *
   * @return {@link Boolean}
   */
  @Bean("hokActive")
  Boolean hokActive() {
    return StringUtils.hasText(this.properties.getHokBaseUri())
        || StringUtils.hasText(this.properties.getDebugHokBaseUri());
  }

  /**
   * Returns the SP entityID bean.
   *
   * @return SP entityID
   */
  @Bean(name = "spEntityID")
  EntityID spEntityID() {
    return new EntityID(this.properties.getEntityId());
  }

  /**
   * Returns the sign service entityID bean.
   *
   * @return sign service entityID
   */
  @Bean(name = "signSpEntityID")
  EntityID signSpEntityID() {
    if (StringUtils.hasText(this.properties.getSignEntityId())) {
      return new EntityID(this.properties.getSignEntityId());
    }
    else if (StringUtils.hasText(this.signSpEntityId)) {
      log.warn("Use sp.sign-entity-id instead of sp-sign.entity-id");
      return new EntityID(this.signSpEntityId);
    }
    throw new BeanCreationException("Missing sp.sign-entity-id");
  }

  @Bean(name = "eidasConnectorEntityID")
  EntityID eidasConnectorEntityID() {
    return new EntityID(this.properties.getEidasConnector().getEntityId());
  }

  @Bean("signCredential")
  X509Credential signCredential() throws Exception {
    return new OpenSamlCredential(this.properties.getCredential().getSign().createCredential());
  }

  @Bean("encryptCredential")
  X509Credential encryptCredential() throws Exception {
    return new OpenSamlCredential(this.properties.getCredential().getDecrypt().createCredential());
  }

  @Bean("mdSignCredential")
  X509Credential mdSignCredential() throws Exception {
    if (this.properties.getCredential().getMdSign() != null) {
      return new OpenSamlCredential(this.properties.getCredential().getMdSign().createCredential());
    }
    else {
      return this.signCredential();
    }
  }

  @Bean
  List<UiLanguage> languages() {
    return this.properties.getUi().getLang();
  }

  @Bean
  AttributeInfoRegistry attributeInfoRegistry() {
    return new AttributeInfoRegistry(this.properties.getUi().getAttributes());
  }

  @Bean
  @ConditionalOnProperty(name = "tomcat.ajp.enabled", havingValue = "true")
  ClientCertificateGetter attributeBasedClientCertificateGetter() {
    return new FromRequestAttributeClientCertificateGetter(this.properties.getMtls().getAttributeName());
  }

  @Bean
  @Profile("!local")
  @ConditionalOnProperty(name = "tomcat.ajp.enabled", matchIfMissing = true, havingValue = "false")
  ClientCertificateGetter headerBasedClientCertificateGetter() {
    return new FromHeaderClientCertificateGetter(this.properties.getMtls().getHeaderName());
  }

  @Bean
  @Profile("local")
  ClientCertificateGetter attributeBasedClientCertificateGetter2() {
    return new FromRequestAttributeClientCertificateGetter(this.properties.getMtls().getAttributeName());
  }

  @Bean("userMessages")
  Map<String, String> userMessages() throws IOException {
    final Map<String, String> userMessages = new HashMap<>();
    for (final Map.Entry<String, Resource> entry : this.properties.getUi().getUserMessageTemplate().entrySet()) {

      try (final InputStream stream = entry.getValue().getInputStream()) {
        userMessages.put(entry.getKey(), new String(stream.readAllBytes(), StandardCharsets.UTF_8));
      }
    }
    return userMessages;
  }

  @Bean
  IdpList idpList(final MetadataProvider metadataProvider,
      @Qualifier("staticIdps") final List<StaticIdpDiscoEntry> staticIdps,
      @Qualifier("spMetadata") final EntityDescriptor spMetadata,
      @Qualifier("hokActive") final Boolean hokActive) {

    // Merge static IdP:s from configuration and those supplied in separate file
    //
    final List<StaticIdpDiscoEntry> idps = new ArrayList<>(
        Optional.ofNullable(this.properties.getDiscovery().getIdp())
        .orElseGet(Collections::emptyList));
    staticIdps.stream()
      .filter(i -> idps.stream().noneMatch(i2 -> i2.getEntityId().equals(i.getEntityId())))
      .forEach(idps::add);

    final IdpList idpList = new IdpList(metadataProvider, spMetadata, idps,
        this.properties.getDiscovery().getBlackList(),
        this.properties.getDiscovery().isIncludeOnlyStatic(),
        hokActive);

    idpList.setCacheTime(this.properties.getDiscovery().getCacheTime());
    idpList.setIgnoreContracts(this.properties.getDiscovery().isIgnoreContracts());

    return idpList;
  }

  @Bean(initMethod = "initialize")
  ResponseProcessor responseProcessor(final MetadataProvider metadataProvider,
      @Qualifier("encryptCredential") final X509Credential encryptCredential) {

    final SwedishEidResponseProcessorImpl responseProcessor = new SwedishEidResponseProcessorImpl();
    responseProcessor.setMetadataResolver(metadataProvider.getMetadataResolver());
    responseProcessor.setDecrypter(new SAMLObjectDecrypter(encryptCredential));
    responseProcessor.setMessageReplayChecker(new InMemoryReplayChecker());
    return responseProcessor;
  }

  @Bean(initMethod = "initialize")
  MetadataProvider metadataProvider() throws Exception {

    final X509Certificate cert = this.properties.getFederation().getMetadata().getValidationCertificate() != null
        ? (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
            this.properties.getFederation().getMetadata().getValidationCertificate().getInputStream())
        : null;

    final Resource location = this.properties.getFederation().getMetadata().getUrl();
    AbstractMetadataProvider provider;
    if (location instanceof UrlResource urlResource && !urlResource.isFile()) {

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

  @Bean("spMetadata")
  EntityDescriptor spMetadata(
      @Value("${server.servlet.context-path}") final String contextPath,
      @Value("${server.port}") final int serverPort,
      @Qualifier("signCredential") final X509Credential signCredential,
      @Qualifier("encryptCredential") final X509Credential encryptCredential) {

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

  @Bean("spEntityDescriptorContainer")
  EntityDescriptorContainer entityDescriptorContainer(
      @Qualifier("spMetadata") final EntityDescriptor spMetadata,
      @Qualifier("mdSignCredential") final X509Credential mdSignCredential) {
    return new EntityDescriptorContainer(spMetadata, mdSignCredential);
  }

  @Bean("signSpMetadata")
  EntityDescriptor signSpMetadata(
      @Value("${server.servlet.context-path}") final String contextPath,
      @Value("${server.port}") final int serverPort,
      @Qualifier("signCredential") final X509Credential signCredential,
      @Qualifier("encryptCredential") final X509Credential encryptCredential) {

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

  @Bean("signSpEntityDescriptorContainer")
  EntityDescriptorContainer signSpEntityDescriptorContainer(
      @Qualifier("signSpMetadata") final EntityDescriptor signSpMetadata,
      @Qualifier("mdSignCredential") final X509Credential mdSignCredential) {
    return new EntityDescriptorContainer(signSpMetadata, mdSignCredential);
  }

  @Bean(name = "spAuthnRequestGenerator", initMethod = "initialize")
  TestMyEidAuthnRequestGenerator spAuthnRequestGenerator(
      @Qualifier("spMetadata") final EntityDescriptor metadata,
      @Qualifier("signCredential") final X509Credential signCredential,
      final MetadataProvider metadataProvider) {

    return new TestMyEidAuthnRequestGenerator(metadata, signCredential, metadataProvider.getMetadataResolver());
  }

  @Bean(name = "signSpAuthnRequestGenerator", initMethod = "initialize")
  TestMyEidAuthnRequestGenerator signSpAuthnRequestGenerator(
      @Qualifier("signSpMetadata") final EntityDescriptor metadata,
      @Qualifier("signCredential") final X509Credential signCredential,
      final MetadataProvider metadataProvider,
      final SignMessageEncrypter signMessageEncrypter) {

    final TestMyEidAuthnRequestGenerator generator =
        new TestMyEidAuthnRequestGenerator(metadata, signCredential, metadataProvider.getMetadataResolver());
    generator.setSignMessageEncrypter(signMessageEncrypter);
    return generator;
  }

  @Bean
  SignMessageEncrypter signMessageEncrypter(final MetadataProvider metadataProvider)
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
          this.properties.getCredential().getDecrypt().createCredential());

      if (AlgorithmDescriptor.AlgorithmType.KeyTransport.equals(algoDesc.getType())
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
