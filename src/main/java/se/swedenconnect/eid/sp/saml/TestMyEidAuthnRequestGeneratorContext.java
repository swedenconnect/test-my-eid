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
package se.swedenconnect.eid.sp.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Customized context for generating authentication requests.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class TestMyEidAuthnRequestGeneratorContext implements SwedishEidAuthnRequestGeneratorContext {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(TestMyEidAuthnRequestGeneratorContext.class);

  /** The special purpose AuthnContextClassRef URI for eIDAS test authentications. */
  public static final @NonNull String EIDAS_PING_LOA = "http://eidas.europa.eu/LoA/test";

  private final HokRequirement hokRequirement;

  private boolean debug;

  private @Nullable String country;

  private boolean ping;

  private @Nullable List<String> requestedAuthnContextUris;

  private @Nullable String signMessage;

  private @Nullable Map<String, String> userMessages;

  private @Nullable String personalIdentityNumberHint;

  private @Nullable String pridHint;

  /**
   * Constructor.
   *
   * @param hokRequirement the Holder-of-key requirement
   */
  public TestMyEidAuthnRequestGeneratorContext(final @NonNull HokRequirement hokRequirement) {
    this.hokRequirement = hokRequirement;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull HokRequirement getHokRequirement() {
    return this.hokRequirement;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {

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

  /** {@inheritDoc} */
  @Override
  public @NonNull AssertionConsumerServiceResolver getAssertionConsumerServiceResolver() {
    return (list) -> list.size() == 1 || !this.debug
        ? list.get(0).getLocation()
        : list.get(1).getLocation();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull SignMessageBuilderFunction getSignMessageBuilderFunction() {
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

  /** {@inheritDoc} */
  @Override
  public @NonNull UserMessageBuilderFunction getUserMessageBuilderFunction() {
    return (e) -> {
      if (this.userMessages == null) {
        return null;
      }
      final UserMessageBuilder builder = UserMessageBuilder.builder()
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

  /** {@inheritDoc} */
  @Override
  public @NonNull PrincipalSelectionBuilderFunction getPrincipalSelectionBuilderFunction() {
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

  /**
   * Assigns whether debug mode is active.
   *
   * @param debug whether debug mode is active
   */
  public void setDebug(final boolean debug) {
    this.debug = debug;
  }

  /**
   * Gets the country.
   *
   * @return the country
   */
  public @Nullable String getCountry() {
    return this.country;
  }

  /**
   * Assigns the country.
   *
   * @param country the country
   */
  public void setCountry(final @Nullable String country) {
    this.country = country;
  }

  /**
   * Assigns whether this is an eIDAS ping request.
   *
   * @param ping whether this is a ping request
   */
  public void setPing(final boolean ping) {
    this.ping = ping;
  }

  /**
   * Assigns the requested authn context uris.
   *
   * @param requestedAuthnContextUris the requested authn context uris
   */
  public void setRequestedAuthnContextUris(final @Nullable List<String> requestedAuthnContextUris) {
    this.requestedAuthnContextUris = requestedAuthnContextUris;
  }

  /**
   * Gets the sign message.
   *
   * @return the sign message
   */
  public @Nullable String getSignMessage() {
    return this.signMessage;
  }

  /**
   * Assigns the sign message.
   *
   * @param signMessage the sign message
   */
  public void setSignMessage(final @Nullable String signMessage) {
    this.signMessage = signMessage;
  }

  /**
   * Gets the user messages.
   *
   * @return the user messages
   */
  public @Nullable Map<String, String> getUserMessages() {
    return this.userMessages;
  }

  /**
   * Assigns the user messages.
   *
   * @param userMessages the user messages
   */
  public void setUserMessages(final @Nullable Map<String, String> userMessages) {
    this.userMessages = userMessages;
  }

  /**
   * Assigns the personal identity number hint.
   *
   * @param personalIdentityNumberHint the personal identity number hint
   */
  public void setPersonalIdentityNumberHint(final @Nullable String personalIdentityNumberHint) {
    this.personalIdentityNumberHint = personalIdentityNumberHint;
  }

  /**
   * Assigns the prid hint.
   *
   * @param pridHint the prid hint
   */
  public void setPridHint(final @Nullable String pridHint) {
    this.pridHint = pridHint;
  }

}
