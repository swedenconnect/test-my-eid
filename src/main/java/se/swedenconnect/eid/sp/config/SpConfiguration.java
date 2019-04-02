/*
 * Copyright 2018-2019 Sweden Connect
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.system.ApplicationTemp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.litsec.opensaml.saml2.common.response.InMemoryReplayChecker;
import se.litsec.opensaml.saml2.common.response.ResponseProcessor;
import se.litsec.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.litsec.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.litsec.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.litsec.opensaml.saml2.metadata.build.SpEntityDescriptorBuilder;
import se.litsec.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.litsec.opensaml.saml2.metadata.provider.MetadataProvider;
import se.litsec.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.litsec.opensaml.utils.ObjectUtils;
import se.litsec.opensaml.utils.X509CertificateUtils;
import se.litsec.opensaml.xmlsec.SAMLObjectDecrypter;
import se.litsec.opensaml.xmlsec.SAMLObjectEncrypter;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.litsec.swedisheid.opensaml.saml2.signservice.SignMessageEncrypter;
import se.litsec.swedisheid.opensaml.saml2.validation.SwedishEidResponseProcessorImpl;
import se.swedenconnect.eid.sp.saml.AuthnRequestGenerator;

/**
 * Configuration for the eIDAS Test SP.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Configuration
@DependsOn("openSAML")
public class SpConfiguration {

  @Value("${sp.entity-id}")
  private String spEntityId;

  @Value("${sign-sp.entity-id}")
  private String signSpEntityId;

  @Value("${sp.debug-base-uri:}")
  private String debugBaseUri;

  @Autowired
  private MetadataConfiguration metadataConfiguration;

  /** Temporary directory for caches. */
  private ApplicationTemp tempDir = new ApplicationTemp();

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

    SwedishEidResponseProcessorImpl responseProcessor = new SwedishEidResponseProcessorImpl();
    responseProcessor.setDecrypter(new SAMLObjectDecrypter(this.encryptCredential().getCredential()));
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
      @Value("${sp.federation.metadata.url}") String federationMetadataUrl,
      @Value("${sp.federation.metadata.validation-certificate}") Resource validationCertificate) throws Exception {

    X509Certificate cert = X509CertificateUtils.decodeCertificate(validationCertificate.getInputStream());

    HttpClientSecurityParameters tlsPars = new HttpClientSecurityParameters();
    tlsPars.setTLSTrustEngine((token, trustBasisCriteria) -> true);

    File backupFile = new File(this.tempDir.getDir(), "metadata-cache.xml");
    HTTPMetadataProvider provider = new HTTPMetadataProvider(federationMetadataUrl, backupFile.getAbsolutePath(), tlsPars);
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
      @Value("${sp.federation.metadata.url}") Resource metadataResource) throws Exception {

    // There is a bug in SpringResourceMetadataProvider, see https://github.com/litsec/opensaml-ext/issues/36, so
    // we have to do a bit of a work-around.
    //
    // SpringResourceMetadataProvider provider = new SpringResourceMetadataProvider(metadataResource);

    EntitiesDescriptor entitiesDescriptor = ObjectUtils.unmarshall(metadataResource.getInputStream(), EntitiesDescriptor.class);
    StaticMetadataProvider provider = new StaticMetadataProvider(entitiesDescriptor);
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
      @Value("${server.servlet.context-path}") String contextPath,
      @Value("${sp.base-uri}") String baseUri,
      @Value("${server.port}") int serverPort) {

    SpEntityDescriptorBuilder builder = new SpEntityDescriptorBuilder();

    builder
      .entityID(this.spEntityID().getEntityID())
      .entityCategories(this.metadataConfiguration.getEntityCategories())
      .authnRequestsSigned(true)
      .wantAssertionsSigned(false)
      .uiInfoExtension(this.metadataConfiguration.getUIInfoElement(baseUri, contextPath))
      .keyDescriptors(
        KeyDescriptorBuilder.builder()
          .use(UsageType.SIGNING)
          .keyName("Signing")
          .certificate(this.signCredential().getCredential().getEntityCertificate())
          .build(),
        KeyDescriptorBuilder.builder()
          .use(UsageType.ENCRYPTION)
          .keyName("Encryption")
          .certificate(this.encryptCredential().getCredential().getEntityCertificate())
          .build())
      .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
      .organization(this.metadataConfiguration.getOrganizationElement())
      .contactPersons(this.metadataConfiguration.getContactPersonElements());

    List<AssertionConsumerService> acs = new ArrayList<>();
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
    builder.assertionConsumerServices(acs);

    return builder.build();
  }

  @Bean("spEntityDescriptorContainer")
  public EntityDescriptorContainer entityDescriptorContainer(@Qualifier("spMetadata") EntityDescriptor spMetadata) {
    return new EntityDescriptorContainer(spMetadata, this.mdSignCredential().getCredential());
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
      @Value("${server.servlet.context-path}") String contextPath,
      @Value("${sp.base-uri}") String baseUri,
      @Value("${server.port}") int serverPort) {

    SpEntityDescriptorBuilder builder = new SpEntityDescriptorBuilder();

    List<String> entityCategories = new ArrayList<>();
    entityCategories.add(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri());
    entityCategories.addAll(this.metadataConfiguration.getEntityCategories());

    builder
      .entityID(this.signSpEntityID().getEntityID())
      .entityCategories(entityCategories)
      .authnRequestsSigned(true)
      .wantAssertionsSigned(true)
      .uiInfoExtension(this.metadataConfiguration.getUIInfoElement(baseUri, contextPath))
      .keyDescriptors(
        KeyDescriptorBuilder.builder()
          .use(UsageType.SIGNING)
          .keyName("Signing")
          .certificate(this.signCredential().getCredential().getEntityCertificate())
          .build(),
        KeyDescriptorBuilder.builder()
          .use(UsageType.ENCRYPTION)
          .keyName("Encryption")
          .certificate(this.encryptCredential().getCredential().getEntityCertificate())
          .build())
      .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
      .organization(this.metadataConfiguration.getOrganizationElement())
      .contactPersons(this.metadataConfiguration.getContactPersonElements());

    List<AssertionConsumerService> acs = new ArrayList<>();
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
    builder.assertionConsumerServices(acs);

    return builder.build();
  }

  @Bean("signSpEntityDescriptorContainer")
  public EntityDescriptorContainer signSpEntityDescriptorContainer(@Qualifier("signSpMetadata") EntityDescriptor signSpMetadata) {
    return new EntityDescriptorContainer(signSpMetadata, this.mdSignCredential().getCredential());
  }

  @Bean("spAuthnRequestGenerator")
  public AuthnRequestGenerator spAuthnRequestGenerator(@Qualifier("spEntityID") EntityID entityID,
      @Qualifier("spMetadata") EntityDescriptor metadata) {
    return new AuthnRequestGenerator(entityID.getEntityID(), metadata);
  }

  @Bean("signSpAuthnRequestGenerator")
  public AuthnRequestGenerator signSpAuthnRequestGenerator(@Qualifier("signSpEntityID") EntityID entityID,
      @Qualifier("signSpMetadata") EntityDescriptor metadata) {
    return new AuthnRequestGenerator(entityID.getEntityID(), metadata);
  }

  @Bean("signCredential")
  @ConfigurationProperties(prefix = "sp.credential.sign")
  public SpCredential signCredential() {
    return new SpCredential();
  }

  @Bean("encryptCredential")
  @ConfigurationProperties(prefix = "sp.credential.decrypt")
  public SpCredential encryptCredential() {
    return new SpCredential();
  }

  @Bean("mdSignCredential")
  @ConfigurationProperties(prefix = "sp.credential.md-sign")
  public SpCredential mdSignCredential() {
    return new SpCredential();
  }

  @Bean
  public SignMessageEncrypter signMessageEncrypter(MetadataProvider metadataProvider) throws ComponentInitializationException {
    return new SignMessageEncrypter(new SAMLObjectEncrypter(metadataProvider));
  }

}
