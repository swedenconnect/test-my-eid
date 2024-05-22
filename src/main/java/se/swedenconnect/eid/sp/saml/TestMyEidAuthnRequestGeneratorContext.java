/*
 * Copyright 2018-2023 Sweden Connect
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
import java.util.List;
import java.util.Map;

import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.xmlsec.encryption.support.EncryptionException;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.MatchValue;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.build.MessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.build.UserMessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.signservice.build.SignMessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;

/**
 * Customized context for generating authentication requests.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Slf4j
public class TestMyEidAuthnRequestGeneratorContext implements SwedishEidAuthnRequestGeneratorContext {

  /** The special purpose AuthnContextClassRef URI for eIDAS test authentications. */
  public static final String EIDAS_PING_LOA = "http://eidas.europa.eu/LoA/test";

  private final HokRequirement hokRequirement;

  @Setter
  private boolean debug;

  @Setter
  @Getter
  private String country;

  @Setter
  private boolean ping;

  @Setter
  private List<String> requestedAuthnContextUris;

  @Setter
  @Getter
  private String signMessage;

  @Setter
  @Getter
  private Map<String, String> userMessages;

  @Setter
  private String personalIdentityNumberHint;

  @Setter
  private String pridHint;

  public TestMyEidAuthnRequestGeneratorContext(final HokRequirement hokRequirement) {
    this.hokRequirement = hokRequirement;
  }

  @Override
  public HokRequirement getHokRequirement() {
    return this.hokRequirement;
  }

  @Override
  public RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {

    if (this.ping) {
      return (list, h) -> RequestedAuthnContextBuilder.builder()
          .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
          .authnContextClassRefs(EIDAS_PING_LOA)
          .build();
    }
    else if (this.requestedAuthnContextUris != null) {
      return (list, h) -> list.isEmpty()
          ? null
          : RequestedAuthnContextBuilder.builder()
              .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
              .authnContextClassRefs(this.requestedAuthnContextUris)
              .build();
    }
    else {
      // TODO
      return SwedishEidAuthnRequestGeneratorContext.super.getRequestedAuthnContextBuilderFunction();
    }
  }

  @Override
  public AssertionConsumerServiceResolver getAssertionConsumerServiceResolver() {
    return (list) -> list.size() == 1 || !this.debug
        ? list.get(0).getLocation()
        : list.get(1).getLocation();
  }

  @Override
  public SignMessageBuilderFunction getSignMessageBuilderFunction() {
    return (metadata, encrypter) -> {
      if (this.signMessage != null) {
        final SignMessage signMessage = SignMessageBuilder.builder()
            .displayEntity(metadata.getEntityID())
            .mimeType(SignMessageMimeTypeEnum.TEXT)
            .mustShow(true)
            .message(this.signMessage)
            .build();

        if (encrypter != null) {
          try {
            encrypter.encrypt(signMessage, metadata.getEntityID());
          }
          catch (final EncryptionException e) {
            log.error("Failed to encrypt SignMessage to {}", metadata.getEntityID(), e);
          }
        }
        return signMessage;
      }
      else {
        return null;
      }
    };
  }

  @Override
  public UserMessageBuilderFunction getUserMessageBuilderFunction() {
    return (e) -> {
      if (this.userMessages == null) {
        return null;
      }
      UserMessageBuilder builder = UserMessageBuilder.builder()
          .mimeType("text/markdown");

      for (final Map.Entry<String, String> entry : this.userMessages.entrySet()) {
        builder.message(MessageBuilder.builder()
            .language(entry.getKey())
            .content(entry.getValue())
            .build());
      }
      return builder.build();
    };
  }

  @Override
  public PrincipalSelectionBuilderFunction getPrincipalSelectionBuilderFunction() {
    return () -> {
      if (this.personalIdentityNumberHint != null || this.pridHint != null) {
        final List<MatchValue> matchValues = new ArrayList<>();
        if (this.personalIdentityNumberHint != null) {
          matchValues.add(MatchValueBuilder.builder()
              .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
              .value(this.personalIdentityNumberHint)
              .build());
        }
        if (this.pridHint != null) {
          matchValues.add(MatchValueBuilder.builder()
              .name(AttributeConstants.ATTRIBUTE_NAME_PRID)
              .value(this.pridHint)
              .build());
        }
        return PrincipalSelectionBuilder.builder()
            .matchValues(matchValues)
            .build();
      }
      else {
        return null;
      }
    };
  }

}
