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
package se.swedenconnect.eid.sp.saml;

import java.util.Optional;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.x509.X509Credential;
import org.springframework.util.StringUtils;

import se.swedenconnect.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.swedenconnect.opensaml.saml2.core.build.ScopingBuilder;
import se.swedenconnect.opensaml.saml2.metadata.HolderOfKeyMetadataSupport;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestGenerationException;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGenerator;

/**
 * Customized {@link AuthnRequestGenerator} for this application.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class TestMyEidAuthnRequestGenerator extends SwedishEidAuthnRequestGenerator {

  /**
   * Constructor.
   *
   * @param spEntityID the SP entityID
   * @param signCredential the signing credential
   * @param metadataResolver the metadata resolver
   */
  public TestMyEidAuthnRequestGenerator(final EntityDescriptor spMetadata, final X509Credential signCredential,
      final MetadataResolver metadataResolver) {
    super(spMetadata, signCredential, metadataResolver);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void addScoping(final AuthnRequestBuilder builder, final AuthnRequestGeneratorContext context,
      final EntityDescriptor idpMetadata) throws RequestGenerationException {

    final String country = ((TestMyEidAuthnRequestGeneratorContext) context).getCountry();
    if (StringUtils.hasText(country)) {
      final String countryUri = "http://id.swedenconnect.se/eidas/1.0/proxy-service/" + country;
      builder.scoping(ScopingBuilder.builder()
          .idpList(null, ScopingBuilder.idpEntry(countryUri, null, null))
          .build());
    }
  }

  public HokSupport getIdpHokSupport(final String idpEntityID) {
    final IDPSSODescriptor descriptor = Optional.ofNullable(this.getIdpMetadata(idpEntityID))
        .map(m -> m.getIDPSSODescriptor(SAMLConstants.SAML20P_NS))
        .orElse(null);

    if (descriptor == null) {
      return HokSupport.NONE;
    }
    boolean hok = false;
    boolean websso = false;
    for (final SingleSignOnService sso : descriptor.getSingleSignOnServices()) {
      if (HolderOfKeyMetadataSupport.isHoKSingleSignOnService(sso)) {
        hok = true;
      }
      else {
        websso = true;
      }
    }
    if (hok) {
      return websso ? HokSupport.BOTH : HokSupport.ONLY_HOK;
    }
    else {
      return HokSupport.NONE;
    }
  }

}
