/*
 * Copyright 2018-2020 Sweden Connect
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import org.joda.time.DateTime;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.DependsOn;
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
import se.litsec.swedisheid.opensaml.saml2.attribute.AttributeConstants;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;
import se.litsec.swedisheid.opensaml.saml2.authentication.psc.MatchValue;
import se.litsec.swedisheid.opensaml.saml2.authentication.psc.PrincipalSelection;
import se.litsec.swedisheid.opensaml.saml2.authentication.psc.build.MatchValueBuilder;
import se.litsec.swedisheid.opensaml.saml2.authentication.psc.build.PrincipalSelectionBuilder;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryMetadataHelper;
import se.litsec.swedisheid.opensaml.saml2.signservice.SignMessageBuilder;
import se.litsec.swedisheid.opensaml.saml2.signservice.SignMessageEncrypter;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.eid.sp.config.SpCredential;

/**
 * Generator for {@code AuthnRequest} messages.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Slf4j
@DependsOn("openSAML")
public class AuthnRequestGenerator extends AbstractAuthnRequestGenerator<AuthnRequestGeneratorInput> {

  /** The federation metadata provider. */
  @Autowired
  private MetadataProvider metadataProvider;

  @Autowired
  @Qualifier("signCredential")
  private SpCredential signCredential;

  @Autowired
  private SignMessageEncrypter signMessageEncrypter;

  /** The SP metadata. */
  private EntityDescriptor spMetadata;

  /** The assertion consumer service URL. */
  private String assertionConsumerServiceUrl;

  /** The assertion consumer service URL for debug. */
  private String debugAssertionConsumerServiceUrl;

  /**
   * Contructor.
   * 
   * @param entityID
   *          the SP entityID
   * @param metadata
   *          the SP metadata
   */
  public AuthnRequestGenerator(String entityID, EntityDescriptor metadata) {
    super(entityID);
    this.spMetadata = metadata;
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

    // For extensions that we may add ...
    Extensions extensions = null;

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

    final boolean isSignatureService = this.isSignatureService();

    // If the input contains a sign message (and we are a signature service)
    // we assign the sign message (encrypted).
    //
    if (input.getSignMessage() != null && isSignatureService) {
      SignMessage signMessage = SignMessageBuilder.builder()
        .displayEntity(input.getPeerEntityID())
        .mimeType(SignMessageMimeTypeEnum.TEXT)
        .mustShow(true)
        .message(input.getSignMessage())
        .build();

      try {
        this.signMessageEncrypter.encrypt(signMessage, input.getPeerEntityID());
      }
      catch (EncryptionException e) {
        throw new RequestGenerationException("Failed to encrypt SignMessage to " + input.getPeerEntityID(), e);
      }
      if (extensions == null) {
        extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
      }
      extensions.getUnknownXMLObjects().add(signMessage);
    }

    // Get the assurance certification URI:s from the IdP metadata
    //
    List<String> assuranceCertificationUris;
    if (input.getRequestedAuthnContextUri() != null) {
      assuranceCertificationUris = Arrays.asList(input.getRequestedAuthnContextUri());
    }
    else {
      assuranceCertificationUris = this.getAssuranceCertificationUris(idp);
    }

    builder.requestedAuthnContext(RequestedAuthnContextBuilder.builder()
      .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
      .authnContextClassRefs(assuranceCertificationUris)
      .build());

    // If country is set, this is a request to the eIDAS connector in which we pass a requested country ...
    //
    if (StringUtils.hasText(input.getCountry())) {
      String countryUri = "http://id.swedenconnect.se/eidas/1.0/proxy-service/" + input.getCountry().toLowerCase();

      IDPList idpList = (IDPList) XMLObjectSupport.buildXMLObject(IDPList.DEFAULT_ELEMENT_NAME);
      idpList.getIDPEntrys().add(ScopingBuilder.idpEntry(countryUri, null, null));
      ScopingBuilder scopingBuilder = ScopingBuilder.builder();
      scopingBuilder.object().setIDPList(idpList);
      builder.scoping(scopingBuilder.build());
    }

    // If the hint for personal number or prid is set (only if the user first authenticates, and then signs),
    // we include the PrincipalSelection extension.
    //
    if (input.getPersonalIdentityNumberHint() != null || input.getPridHint() != null) {
      List<MatchValue> matchValues = new ArrayList<>();
      if (input.getPersonalIdentityNumberHint() != null) {
        matchValues.add(MatchValueBuilder.builder()
          .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
          .value(input.getPersonalIdentityNumberHint())
          .build());
      }
      if (input.getPridHint() != null) {
        matchValues.add(MatchValueBuilder.builder()
          .name(AttributeConstants.ATTRIBUTE_NAME_PRID)
          .value(input.getPridHint())
          .build());
      }
      PrincipalSelection ps = PrincipalSelectionBuilder.builder()
        .matchValues(matchValues)
        .build();

      if (extensions == null) {
        extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
      }
      extensions.getUnknownXMLObjects().add(ps);
    }

    // We are done ...
    //
    if (extensions != null && extensions.hasChildren()) {
      builder.extensions(extensions);
    }
    AuthnRequest authnRequest = builder.build();

    if (log.isTraceEnabled()) {
      log.debug("Sweden Connect SP sending AuthnRequest: {}", ObjectUtils.toStringSafe(authnRequest));
    }

    return this.buildRequestHttpObject(authnRequest, input, serviceUrl.getBinding(), serviceUrl.getLocation(), idp);
  }

  /**
   * Based on which assurance levels the IdP declares we return a list of URIs to include in our request.
   * 
   * @param metadata
   *          the IdP metadata
   * @return a list of URIs
   */
  private List<String> getAssuranceCertificationUris(EntityDescriptor metadata) {

    List<String> assuranceCertificationUris = new ArrayList<>();

    Predicate<String> filterPredicate;

    // Since we implement the latest version of the technical framework we no longer
    // want to use the sigmessage URI:s. Even if this is a signservice ...
    //
    filterPredicate = u -> {
      LoaEnum e = LoaEnum.parse(u);
      return e != null ? !e.isSignatureMessageUri() : true;
    };

    MetadataUtils.getEntityAttributes(metadata)
      .ifPresent(attrs -> attrs.getAttributes()
        .stream()
        .filter(a -> "urn:oasis:names:tc:SAML:attribute:assurance-certification".equals(a.getName()))
        .map(AttributeUtils::getAttributeStringValues)
        .flatMap(List::stream)
        .distinct()
        .filter(filterPredicate)
        .forEach(assuranceCertificationUris::add));

    if (assuranceCertificationUris.isEmpty()) {
      log.warn("IdP '{}' does not specify assurance certification URI - defaulting to {}", metadata.getEntityID(),
        LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_LOA3);
      assuranceCertificationUris.add(LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_LOA3);
    }

    return assuranceCertificationUris;
  }

  /**
   * Predicate that tells if the entity that we are serving is a signature service SP.
   * 
   * @return {@code true} if this is a signature service, and {@code false} otherwise
   */
  private boolean isSignatureService() {
    return EntityCategoryMetadataHelper.getEntityCategories(this.spMetadata)
      .stream()
      .filter(c -> c.equals(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri()))
      .findFirst()
      .isPresent();
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
