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
package se.swedenconnect.eid.sp.model;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
public class LastAuthentication {

  /** The IdP that authenticated the user. */
  private final @Nullable String idp;

  /** User's given name (may be null). */
  private final @Nullable String givenName;

  /** User's surname (may be null). */
  private final @Nullable String surName;

  /** User display name (may be null). */
  private final @Nullable String displayName;

  /** The personal identity number (may be null). */
  private final @Nullable String personalIdentityNumber;

  /** The prid attribute (may be null). */
  private final @Nullable String prid;

  /** The country attribute (may be null). */
  private final @Nullable String country;

  /** The AuthnContext to request. */
  private final @Nullable String authnContextUri;

  private boolean hokUsed = false;

  /**
   * Constructor.
   *
   * @param authnResult authentication result
   */
  public LastAuthentication(final @NonNull ResponseProcessingResult authnResult) {
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
  public boolean isIdentityMatch(final @NonNull List<Attribute> attributes) {
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

  /**
   * Gets the IdP that authenticated the user.
   *
   * @return the IdP that authenticated the user
   */
  public @Nullable String getIdp() {
    return this.idp;
  }

  /**
   * Gets the given name.
   *
   * @return the given name
   */
  public @Nullable String getGivenName() {
    return this.givenName;
  }

  /**
   * Gets the sur name.
   *
   * @return the sur name
   */
  public @Nullable String getSurName() {
    return this.surName;
  }

  /**
   * Gets the display name.
   *
   * @return the display name
   */
  public @Nullable String getDisplayName() {
    return this.displayName;
  }

  /**
   * Gets the personal identity number (may be null).
   *
   * @return the personal identity number (may be null)
   */
  public @Nullable String getPersonalIdentityNumber() {
    return this.personalIdentityNumber;
  }

  /**
   * Gets the prid attribute (may be null).
   *
   * @return the prid attribute (may be null)
   */
  public @Nullable String getPrid() {
    return this.prid;
  }

  /**
   * Gets the country attribute (may be null).
   *
   * @return the country attribute (may be null)
   */
  public @Nullable String getCountry() {
    return this.country;
  }

  /**
   * Gets the AuthnContext to request.
   *
   * @return the AuthnContext to request
   */
  public @Nullable String getAuthnContextUri() {
    return this.authnContextUri;
  }

  /**
   * Tells whether Holder-of-key was used for the authentication.
   *
   * @return {@code true} if Holder-of-key was used
   */
  public boolean isHokUsed() {
    return this.hokUsed;
  }

  /**
   * Assigns whether Holder-of-key was used for the authentication.
   *
   * @param hokUsed whether Holder-of-key was used
   */
  public void setHokUsed(final boolean hokUsed) {
    this.hokUsed = hokUsed;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "LastAuthentication(idp=" + this.idp
        + ", givenName=" + this.givenName
        + ", surName=" + this.surName
        + ", displayName=" + this.displayName
        + ", personalIdentityNumber=" + this.personalIdentityNumber
        + ", prid=" + this.prid
        + ", country=" + this.country
        + ", authnContextUri=" + this.authnContextUri
        + ", hokUsed=" + this.hokUsed
        + ")";
  }

}
