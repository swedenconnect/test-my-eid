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
package se.swedenconnect.eid.sp.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.opensaml.saml.saml2.core.Attribute;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;

import java.util.List;
import java.util.Optional;

/**
 * Model object holding information from the last authentication operation. Used by "authentication for signature".
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@ToString
public class LastAuthentication {

  /** The IdP that authenticated the user. */
  @Getter
  private final String idp;

  /** User's given name (may be null). */
  @Getter
  private final String givenName;

  /** User's surname (may be null). */
  @Getter
  private final String surName;

  /** User display name (may be null). */
  @Getter
  private final String displayName;

  /** The personal identity number (may be null). */
  @Getter
  private final String personalIdentityNumber;

  /** The prid attribute (may be null). */
  @Getter
  private final String prid;

  /** The country attribute (may be null). */
  @Getter
  private final String country;

  /** The AuthnContext to request. */
  @Getter
  private final String authnContextUri;

  @Getter
  @Setter
  private boolean hokUsed = false;

  /**
   * Constructor.
   *
   * @param authnResult authentication result
   */
  public LastAuthentication(final ResponseProcessingResult authnResult) {
    this.idp = authnResult.getIssuer();
    this.personalIdentityNumber = Optional.ofNullable(
            AttributeUtils.getAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
                authnResult.getAttributes()))
        .map(AttributeUtils::getAttributeStringValue)
        .orElse(null);
    this.givenName = Optional.ofNullable(
            AttributeUtils.getAttribute(
                AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, authnResult.getAttributes()))
        .map(AttributeUtils::getAttributeStringValue)
        .orElse(null);
    this.surName = Optional.ofNullable(
            AttributeUtils.getAttribute(AttributeConstants.ATTRIBUTE_NAME_SN, authnResult.getAttributes()))
        .map(AttributeUtils::getAttributeStringValue)
        .orElse(null);
    this.displayName = Optional.ofNullable(
            AttributeUtils.getAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME, authnResult.getAttributes()))
        .map(AttributeUtils::getAttributeStringValue)
        .orElse(null);
    this.prid = Optional.ofNullable(
            AttributeUtils.getAttribute(AttributeConstants.ATTRIBUTE_NAME_PRID, authnResult.getAttributes()))
        .map(AttributeUtils::getAttributeStringValue)
        .orElse(null);
    this.country = Optional.ofNullable(
            AttributeUtils.getAttribute(AttributeConstants.ATTRIBUTE_NAME_C, authnResult.getAttributes()))
        .map(AttributeUtils::getAttributeStringValue)
        .orElse(null);
    this.authnContextUri = authnResult.getAuthnContextClassUri();
  }

  /**
   * Given the list of attributes, this method checks if they match this object.
   *
   * @param attributes attributes
   * @return {@code true} if we have a match for identities, and {@code false} otherwise
   */
  public boolean isIdentityMatch(final List<Attribute> attributes) {
    for (final Attribute a : attributes) {
      if (this.personalIdentityNumber != null
          && AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER.equals(a.getName())) {
        return this.personalIdentityNumber.equals(AttributeUtils.getAttributeStringValue(a));
      }
      if (this.prid != null && AttributeConstants.ATTRIBUTE_NAME_PRID.equals(a.getName())) {
        return this.prid.equals(AttributeUtils.getAttributeStringValue(a));
      }
    }
    return false;
  }

}
