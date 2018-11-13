/*
 * Copyright 2018 Sweden Connect
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
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.system.ApplicationTemp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import se.litsec.opensaml.saml2.common.response.InMemoryReplayChecker;
import se.litsec.opensaml.saml2.common.response.ResponseProcessor;
import se.litsec.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.litsec.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.litsec.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.litsec.opensaml.saml2.metadata.build.SpEntityDescriptorBuilder;
import se.litsec.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.litsec.opensaml.saml2.metadata.provider.MetadataProvider;
import se.litsec.opensaml.saml2.metadata.provider.spring.SpringResourceMetadataProvider;
import se.litsec.opensaml.utils.X509CertificateUtils;
import se.litsec.opensaml.xmlsec.SAMLObjectDecrypter;
import se.litsec.swedisheid.opensaml.saml2.validation.SwedishEidResponseProcessorImpl;

/**
 * Configuration for the eIDAS Test SP.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@Configuration
@DependsOn("openSAML")
public class SpConfiguration {

  @Value("${sp.entity-id}")
  private String spEntityId;
  
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

    SpringResourceMetadataProvider provider = new SpringResourceMetadataProvider(metadataResource);
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
  @Bean
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
          .keyName("Signing")
          .certificate(this.signCredential().getCredential().getEntityCertificate())
          .build(),
        KeyDescriptorBuilder.builder()
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

  @Bean
  public EntityDescriptorContainer entityDescriptorContainer(EntityDescriptor spMetadata) {
    return new EntityDescriptorContainer(spMetadata, this.mdSignCredential().getCredential());
  }  

  @Bean("signCredential")
  @ConfigurationProperties(prefix = "sp.credential.sign")
  public SpCredential signCredential() {
    return new SpCredential();
  }

  @Bean("encryptCredential")
  @ConfigurationProperties(prefix = "sp.credential.encrypt")
  public SpCredential encryptCredential() {
    return new SpCredential();
  }

  @Bean("mdSignCredential")
  @ConfigurationProperties(prefix = "sp.credential.md-sign")
  public SpCredential mdSignCredential() {
    return new SpCredential();
  }

}
