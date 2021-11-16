/*
 * Copyright 2018-2021 Sweden Connect
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
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
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.system.ApplicationTemp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import lombok.Setter;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.swedenconnect.eid.sp.saml.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
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

/**
 * Configuration for the eIDAS Test SP.
 *
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Configuration
@DependsOn("openSAML")
public class SpConfiguration implements InitializingBean {

  @Setter
  @Value("${sp.entity-id}")
  private String spEntityId;

  @Setter
  @Value("${sign-sp.entity-id}")
  private String signSpEntityId;

  /** The Base URI when debugging. */
  @Setter
  @Value("${sp.debug-base-uri:}")
  private String debugBaseUri;

  @Setter
  @Autowired
  private MetadataConfiguration metadataConfiguration;

  @Setter
  @Autowired
  @Qualifier("signCredential")
  private X509Credential signCredential;

  @Setter
  @Autowired
  @Qualifier("encryptCredential")
  private X509Credential encryptCredential;

  @Setter
  @Autowired
  @Qualifier("mdSignCredential")
  private X509Credential mdSignCredential;

  /** Temporary directory for caches. */
  private final ApplicationTemp tempDir = new ApplicationTemp();

  /** Algorithm requirements for encryption. */
  private List<EncryptionMethod> encryptionMethods;

  /**
   * Returns the SP entityID bean.
   *
   * @return SP entityID
   */
  @Bean(name = "spEntityID")
  public EntityID spEntityID() {
    return new EntityID(this.spEntityId);
  }

  /**
   * Returns the sign service entityID bean.
   *
   * @return sign service entityID
   */
  @Bean(name = "signSpEntityID")
  public EntityID signSpEntityID() {
    return new EntityID(this.signSpEntityId);
  }

  /**
   * The response processor.
   *
   * @return the response processor
   * @throws Exception
   *           for errors
   */
  @Bean
  public ResponseProcessor responseProcessor() throws Exception {

    final SwedishEidResponseProcessorImpl responseProcessor = new SwedishEidResponseProcessorImpl();
    responseProcessor.setDecrypter(new SAMLObjectDecrypter(this.encryptCredential));
    responseProcessor.setMessageReplayChecker(new InMemoryReplayChecker());
    responseProcessor.initialize();
    return responseProcessor;
  }

  /**
   * Returns the metadata provider that downloads the federation metadata.
   *
   * @param federationMetadataUrl
   *          the federation metadata URL
   * @param validationCertificate
   *          the metadata validation certificate
   * @return a metadata provider
   * @throws Exception
   *           for init errors
   */
  @Bean
  @Profile("!local")
  public MetadataProvider metadataProvider(
      @Value("${sp.federation.metadata.url}") final String federationMetadataUrl,
      @Value("${sp.federation.metadata.validation-certificate}") final Resource validationCertificate) throws Exception {

    final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
      .generateCertificate(validationCertificate.getInputStream());

    final File backupFile = new File(this.tempDir.getDir(), "metadata-cache.xml");
    final HTTPMetadataProvider provider = new HTTPMetadataProvider(federationMetadataUrl, backupFile.getAbsolutePath(),
      HTTPMetadataProvider.createDefaultHttpClient(null /* trust all */, new DefaultHostnameVerifier()));
    provider.setPerformSchemaValidation(false);
    provider.setSignatureVerificationCertificate(cert);
    provider.initialize();
    return provider;
  }

  /**
   * Returns a static metadata provider for local testing.
   *
   * @param metadataResource
   *          the resource holding the metadata
   * @return a metadata provider
   * @throws Exception
   *           for init errors
   */
  @Bean
  @Profile("local")
  public MetadataProvider localMetadataProvider(
      @Value("${sp.federation.metadata.url}") final Resource metadataResource) throws Exception {

    final Element element = XMLObjectProviderRegistrySupport.getParserPool()
      .parse(metadataResource.getInputStream()).getDocumentElement();
    final StaticMetadataProvider provider = new StaticMetadataProvider(element);
    provider.setPerformSchemaValidation(false);
    provider.initialize();
    return provider;
  }

  /**
   * Returns the SP metadata.
   *
   * @param contextPath
   *          the context path for the application (needed when building URL:s)
   * @param baseUri
   *          the base URI for the application
   * @param serverPort
   *          the server port (for building debug AssertionConsumerServiceURL locations)
   * @return the SP metadata (entity descriptor)
   */
  @Bean("spMetadata")
  public EntityDescriptor spMetadata(
      @Value("${server.servlet.context-path}") final String contextPath,
      @Value("${sp.base-uri}") final String baseUri,
      @Value("${server.port}") final int serverPort) {

    final List<AssertionConsumerService> acs = new ArrayList<>();
    acs.add(AssertionConsumerServiceBuilder.builder()
      .binding(SAMLConstants.SAML2_POST_BINDING_URI)
      .location(String.format("%s%s/saml2/post", baseUri, contextPath.equals("/") ? "" : contextPath))
      .index(0)
      .isDefault(true)
      .build());

    if (StringUtils.hasText(this.debugBaseUri)) {
      acs.add(AssertionConsumerServiceBuilder.builder()
        .binding(SAMLConstants.SAML2_POST_BINDING_URI)
        .location(String.format("%s%s/saml2/post", this.debugBaseUri.trim(), contextPath.equals("/") ? "" : contextPath))
        .index(1)
        .isDefault(false)
        .build());
    }

    return EntityDescriptorBuilder.builder()
      .entityID(this.spEntityID().getEntityID())
      .extensions(ExtensionsBuilder.builder()
        .extension(EntityAttributesBuilder.builder()
          .entityCategoriesAttribute(this.metadataConfiguration.getEntityCategories())
          .build())
        .build())
      .ssoDescriptor(SPSSODescriptorBuilder.builder()
        .authnRequestsSigned(true)
        .wantAssertionsSigned(false)
        .extensions(ExtensionsBuilder.builder()
          .extension(this.metadataConfiguration.getUIInfoElement(baseUri, contextPath))
          .build())
        .keyDescriptors(
          KeyDescriptorBuilder.builder()
            .use(UsageType.SIGNING)
            .keyName("Signing")
            .certificate(this.signCredential.getEntityCertificate())
            .build(),
          KeyDescriptorBuilder.builder()
            .use(UsageType.ENCRYPTION)
            .keyName("Encryption")
            .certificate(this.encryptCredential.getEntityCertificate())
            .encryptionMethodsExt(this.encryptionMethods)
            .build())
        .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
        .attributeConsumingServices(this.metadataConfiguration.getAttributeConsumingService())
        .assertionConsumerServices(acs)
        .build())
      .organization(this.metadataConfiguration.getOrganizationElement())
      .contactPersons(this.metadataConfiguration.getContactPersonElements())
      .build();
  }

  @Bean("spEntityDescriptorContainer")
  public EntityDescriptorContainer entityDescriptorContainer(@Qualifier("spMetadata") final EntityDescriptor spMetadata) {
    return new EntityDescriptorContainer(spMetadata, this.mdSignCredential);
  }

  /**
   * Returns the metadata for the signature service SP.
   *
   * @param contextPath
   *          the context path for the application (needed when building URL:s)
   * @param baseUri
   *          the base URI for the application
   * @param serverPort
   *          the server port (for building debug AssertionConsumerServiceURL locations)
   * @return the SP metadata (entity descriptor)
   */
  @Bean("signSpMetadata")
  public EntityDescriptor signSpMetadata(
      @Value("${server.servlet.context-path}") final String contextPath,
      @Value("${sp.base-uri}") final String baseUri,
      @Value("${server.port}") final int serverPort) {

    final List<AssertionConsumerService> acs = new ArrayList<>();
    acs.add(AssertionConsumerServiceBuilder.builder()
      .binding(SAMLConstants.SAML2_POST_BINDING_URI)
      .location(String.format("%s%s/saml2/sign", baseUri, contextPath.equals("/") ? "" : contextPath))
      .index(0)
      .isDefault(true)
      .build());

    if (StringUtils.hasText(this.debugBaseUri)) {
      acs.add(AssertionConsumerServiceBuilder.builder()
        .binding(SAMLConstants.SAML2_POST_BINDING_URI)
        .location(String.format("%s%s/saml2/sign", this.debugBaseUri.trim(), contextPath.equals("/") ? "" : contextPath))
        .index(1)
        .isDefault(false)
        .build());
    }

    final List<String> entityCategories = new ArrayList<>();
    entityCategories.add(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri());
    entityCategories.addAll(this.metadataConfiguration.getEntityCategories());

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
          .extension(this.metadataConfiguration.getUIInfoElement(baseUri, contextPath))
          .build())
        .keyDescriptors(
          KeyDescriptorBuilder.builder()
            .use(UsageType.SIGNING)
            .keyName("Signing")
            .certificate(this.signCredential.getEntityCertificate())
            .build(),
          KeyDescriptorBuilder.builder()
            .use(UsageType.ENCRYPTION)
            .keyName("Encryption")
            .certificate(this.encryptCredential.getEntityCertificate())
            .encryptionMethodsExt(this.encryptionMethods)
            .build())
        .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
        .attributeConsumingServices(this.metadataConfiguration.getAttributeConsumingService())
        .assertionConsumerServices(acs)
        .build())
      .organization(this.metadataConfiguration.getOrganizationElement())
      .contactPersons(this.metadataConfiguration.getContactPersonElements())
      .build();
  }

  @Bean("signSpEntityDescriptorContainer")
  public EntityDescriptorContainer signSpEntityDescriptorContainer(@Qualifier("signSpMetadata") final EntityDescriptor signSpMetadata) {
    return new EntityDescriptorContainer(signSpMetadata, this.mdSignCredential);
  }

  @Bean("spAuthnRequestGenerator")
  public AuthnRequestGenerator spAuthnRequestGenerator(@Qualifier("spEntityID") final EntityID entityID,
      @Qualifier("spMetadata") final EntityDescriptor metadata) {
    return new AuthnRequestGenerator(entityID.getEntityID(), metadata);
  }

  @Bean("signSpAuthnRequestGenerator")
  public AuthnRequestGenerator signSpAuthnRequestGenerator(@Qualifier("signSpEntityID") final EntityID entityID,
      @Qualifier("signSpMetadata") final EntityDescriptor metadata) {
    return new AuthnRequestGenerator(entityID.getEntityID(), metadata);
  }

  @Bean
  public SignMessageEncrypter signMessageEncrypter(final MetadataProvider metadataProvider) throws ComponentInitializationException {
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
      if (AlgorithmDescriptor.AlgorithmType.KeyTransport.equals(algoDesc.getType())
          && AlgorithmSupport.credentialSupportsAlgorithmForEncryption(this.encryptCredential, algoDesc)) {
        final EncryptionMethod method = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
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
              final OAEPparams oaepParams = (OAEPparams) XMLObjectSupport.buildXMLObject(OAEPparams.DEFAULT_ELEMENT_NAME);
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
      final EncryptionMethod method = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
      method.setAlgorithm(algo);
      this.encryptionMethods.add(method);
    }
  }

}
