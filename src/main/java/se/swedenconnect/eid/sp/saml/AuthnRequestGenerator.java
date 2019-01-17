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
package se.swedenconnect.eid.sp.saml;

import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.litsec.opensaml.saml2.attribute.AttributeUtils;
import se.litsec.opensaml.saml2.common.request.AbstractAuthnRequestGenerator;
import se.litsec.opensaml.saml2.common.request.RequestGenerationException;
import se.litsec.opensaml.saml2.common.request.RequestHttpObject;
import se.litsec.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.litsec.opensaml.saml2.core.build.NameIDPolicyBuilder;
import se.litsec.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.litsec.opensaml.saml2.core.build.ScopingBuilder;
import se.litsec.opensaml.saml2.metadata.MetadataUtils;
import se.litsec.opensaml.saml2.metadata.PeerMetadataResolver;
import se.litsec.opensaml.saml2.metadata.provider.MetadataProvider;
import se.litsec.opensaml.utils.ObjectUtils;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;
import se.swedenconnect.eid.sp.config.EntityID;
import se.swedenconnect.eid.sp.config.SpCredential;

/**
 * Generator for {@code AuthnRequest} messages.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Slf4j
@Service
@DependsOn("openSAML")
public class AuthnRequestGenerator extends AbstractAuthnRequestGenerator<AuthnRequestGeneratorInput> {

  /** The federation metadata provider. */
  @Autowired
  private MetadataProvider metadataProvider;

  /** The SP metadata. */
  @Autowired
  private EntityDescriptor spMetadata;

  @Autowired
  @Qualifier("signCredential")
  private SpCredential signCredential;

  /** The assertion consumer service URL. */
  private String assertionConsumerServiceUrl;

  /** The assertion consumer service URL for debug. */
  private String debugAssertionConsumerServiceUrl;

  /**
   * Contructor.
   * 
   * @param spEntityID
   *          the SP entityID
   */
  public AuthnRequestGenerator(@Qualifier("spEntityID") EntityID spEntityID) {
    super(spEntityID.getEntityID());
    this.setName("Sweden Connect Test SP");
  }

  /**
   * See {@link #generateRequest(AuthnRequestGeneratorInput, PeerMetadataResolver)}.
   * 
   * @param input
   *          request input
   * @return a request object
   * @throws RequestGenerationException
   *           for generation errors
   */
  public RequestHttpObject<AuthnRequest> generateRequest(AuthnRequestGeneratorInput input)
      throws RequestGenerationException {

    PeerMetadataResolver pmr = new PeerMetadataResolver() {

      @Override
      public EntityDescriptor getMetadata(String entityID) {
        try {
          return metadataProvider.getEntityDescriptor(entityID).orElse(null);
        }
        catch (ResolverException e) {
          log.error("Failed to get metadata for IdP", e);
          return null;
        }
      }
    };

    return this.generateRequest(input, pmr);
  }

  /** {@inheritDoc} */
  @Override
  public RequestHttpObject<AuthnRequest> generateRequest(AuthnRequestGeneratorInput input, PeerMetadataResolver metadataResolver)
      throws RequestGenerationException {

    log.debug("Generating AuthnRequest for IdP '{}' ...", input.getPeerEntityID());

    // IdP metadata
    final EntityDescriptor idp = this.getPeerMetadata(input, metadataResolver);

    // Find out where to send the request (and with which binding).
    //
    SingleSignOnService serviceUrl = this.getSingleSignOnService(idp, input);

    // Start building the request ...
    //
    AuthnRequestBuilder builder = AuthnRequestBuilder.builder()
      .id(this.generateID())
      .destination(serviceUrl.getLocation())
      .issueInstant(new DateTime())
      .issuer(this.getEntityID())
      .forceAuthn(true)
      .isPassive(false);

    // Assign assertion consumer URL (with support for debug).
    //
    if (input.isDebug() && this.debugAssertionConsumerServiceUrl != null) {
      builder.assertionConsumerServiceURL(this.debugAssertionConsumerServiceUrl);
    }
    else {
      builder.assertionConsumerServiceURL(this.assertionConsumerServiceUrl);
    }

    // Use a NameID format that the IdP supports ...
    //
    IDPSSODescriptor ssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (ssoDescriptor == null) {
      throw new RequestGenerationException("Invalid IdP metadata - Missing IDPSSODescriptor");
    }
    if (ssoDescriptor.getNameIDFormats().stream().filter(f -> NameID.PERSISTENT.equals(f.getFormat())).findFirst().isPresent()) {
      builder.nameIDPolicy(NameIDPolicyBuilder.builder().format(NameID.PERSISTENT).allowCreate(true).build());
    }
    else if (ssoDescriptor.getNameIDFormats().stream().filter(f -> NameID.TRANSIENT.equals(f.getFormat())).findFirst().isPresent()) {
      builder.nameIDPolicy(NameIDPolicyBuilder.builder().format(NameID.TRANSIENT).allowCreate(true).build());
    }
    else {
      log.info("IdP '{}' does not declare any supported NameID formats in metadata - Leaving NameIDPolicy out from AuthnRequest",
        input.getPeerEntityID());
    }

    // Get the assurance certification URI:s from the IdP metadata and pass all of them (except for sigmessage URI:s).
    //
    Predicate<String> notSigMessageUri = u -> {
      LoaEnum e = LoaEnum.parse(u);
      return e != null ? !e.isSignatureMessageUri() : true;
    };

    List<String> assuranceCertificationUris = MetadataUtils.getEntityAttributes(idp)
      .map(attrs -> attrs.getAttributes()
        .stream()
        .filter(a -> "urn:oasis:names:tc:SAML:attribute:assurance-certification".equals(a.getName()))
        .map(AttributeUtils::getAttributeStringValues)
        .flatMap(List::stream)
        .distinct()
        .filter(notSigMessageUri)
        .collect(Collectors.toList()))
      .orElse(Collections.emptyList());

    if (!assuranceCertificationUris.isEmpty()) {
      builder.requestedAuthnContext(RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
        .authnContextClassRefs(assuranceCertificationUris)
        .build());
    }
    else {
      log.warn("IdP '{}' does not specify assurance certification URI - defaulting to {}", input.getPeerEntityID(), LoaEnum.LOA_3.getUri());
      builder.requestedAuthnContext(RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
        .authnContextClassRefs(LoaEnum.LOA_3.getUri())
        .build());
    }
    
    // If country is set, this is a request to the eIDAS connector in which we pass a requested country ...
    //
    if (StringUtils.hasText(input.getCountry())) {
      String countryUri = "http://id.swedenconnect.se/eidas/1.0/proxy-service/" + input.getCountry().toLowerCase();
      
      IDPList idpList = ObjectUtils.createSamlObject(IDPList.class);
      idpList.getIDPEntrys().add(ScopingBuilder.idpEntry(countryUri, null, null));
      ScopingBuilder scopingBuilder = ScopingBuilder.builder(); 
      scopingBuilder.object().setIDPList(idpList);
      builder.scoping(scopingBuilder.build());
    }

    // We are done ...
    //
    AuthnRequest authnRequest = builder.build();

    if (log.isTraceEnabled()) {
      log.debug("Sweden Connect SP sending AuthnRequest: {}", ObjectUtils.toStringSafe(authnRequest));
    }

    return this.buildRequestHttpObject(authnRequest, input, serviceUrl.getBinding(), serviceUrl.getLocation());
  }

  /**
   * Returns the redirect binding.
   */
  @Override
  protected String getDefaultBinding() {
    return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
  }

  @Override
  public void afterPropertiesSet() throws Exception {

    this.setSigningCredentials(this.signCredential.getCredential());

    super.afterPropertiesSet();

    SPSSODescriptor descriptor = this.spMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    this.assertionConsumerServiceUrl = descriptor.getAssertionConsumerServices().get(0).getLocation();
    if (descriptor.getAssertionConsumerServices().size() > 1) {
      this.debugAssertionConsumerServiceUrl = descriptor.getAssertionConsumerServices().get(1).getLocation();
    }
  }

}
