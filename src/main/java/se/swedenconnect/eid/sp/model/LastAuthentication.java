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
package se.swedenconnect.eid.sp.model;

import java.util.List;

import org.opensaml.saml.saml2.core.Attribute;

import lombok.Getter;
import lombok.ToString;
import se.litsec.opensaml.saml2.attribute.AttributeUtils;
import se.litsec.opensaml.saml2.common.response.ResponseProcessingResult;
import se.litsec.swedisheid.opensaml.saml2.attribute.AttributeConstants;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;

/**
 * Model object holding information from the last authentication operation. Used by "authentication for signature".
 * 
 * @author Martin Lindström (martin@idsec.se)
 */
@ToString
public class LastAuthentication {

  /** The IdP that authenticated the user. */
  @Getter
  private String idp;

  /** User's given name (may be null). */
  @Getter
  private String givenName;

  /** The personal identity number (may be null). */
  @Getter
  private String personalIdentityNumber;

  /** The prid attribute (may be null). */
  @Getter
  private String prid;

  /** The AuthnContext to request. */
  @Getter
  private String signMessageAuthnContextUri;

  /**
   * Constructor.
   * 
   * @param authnResult
   *          authentication result
   */
  public LastAuthentication(ResponseProcessingResult authnResult) {
    this.idp = authnResult.getIssuer();
    this.personalIdentityNumber = AttributeUtils.getAttribute(
      AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, authnResult.getAttributes())
      .map(AttributeUtils::getAttributeStringValue)
      .orElse(null);
    this.givenName = AttributeUtils.getAttribute(
      AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, authnResult.getAttributes())
      .map(AttributeUtils::getAttributeStringValue)
      .orElse(null);
    this.prid = AttributeUtils.getAttribute(
      AttributeConstants.ATTRIBUTE_NAME_PRID, authnResult.getAttributes())
      .map(AttributeUtils::getAttributeStringValue)
      .orElse(null);
    this.signMessageAuthnContextUri = toSigMessageUri(authnResult.getAuthnContextClassUri());
  }

  /**
   * Converts a LoA URI to its corresponding sigmessage URI.
   * 
   * @param loa
   *          the LoA URI to convert
   * @return the corresponding sigmessage URI, or {@code null} if no mapping is found
   */
  private static String toSigMessageUri(String loa) {
    LoaEnum loaEnum = LoaEnum.parse(loa);
    if (loaEnum == null) {
      return null;
    }
    LoaEnum sigMsgLoa = LoaEnum.plusSigMessage(loaEnum);
    return sigMsgLoa != null ? sigMsgLoa.getUri() : null;
  }

  /**
   * Given the list of attributes, this method checks if they match this object.
   * 
   * @param attributes
   *          attributes
   * @return {@code true} if we have a match for identities, and {@code false} otherwise
   */
  public boolean isIdentityMatch(List<Attribute> attributes) {
    for (Attribute a : attributes) {
      if (this.personalIdentityNumber != null && AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER.equals(a.getName())) {
        return this.personalIdentityNumber.equals(AttributeUtils.getAttributeStringValue(a));
      }
      if (this.prid != null && AttributeConstants.ATTRIBUTE_NAME_PRID.equals(a.getName())) {
        return this.prid.equals(AttributeUtils.getAttributeStringValue(a));
      }
    }
    return false;
  }

}
