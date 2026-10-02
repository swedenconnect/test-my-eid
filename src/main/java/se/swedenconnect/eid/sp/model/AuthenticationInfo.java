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

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Model class for the information to display about an authentication.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class AuthenticationInfo {

  /** The SAML attributes. */
  private @Nullable List<AttributeInfo> attributes;

  /** The SAML attributes (advanced, i.e., not displayed unless asked for). */
  private @Nullable List<AttributeInfo> advancedAttributes;

  /** The LoA URI. */
  private @Nullable String loaUri;

  /** The message code for level of assurance. */
  private @Nullable String loaLevelMessageCode;

  /** The message code for a descriptive string for LoA. */
  private @Nullable String loaLevelDescriptionCode;

  /** Message code for notified/non-notified text (eIDAS only). */
  private @Nullable String notifiedInfoMessageCode;

  /** Flag telling whether the info holds information about an eIDAS assertion or not. */
  private boolean eidasAssertion = false;

  /**
   * Gets the SAML attributes.
   *
   * @return the attributes (never null)
   */
  public @NonNull List<AttributeInfo> getAttributes() {
    if (this.attributes == null) {
      this.attributes = new ArrayList<>();
    }
    return this.attributes;
  }

  /**
   * Gets the advanced SAML attributes.
   *
   * @return the advanced attributes (never null)
   */
  public @NonNull List<AttributeInfo> getAdvancedAttributes() {
    if (this.advancedAttributes == null) {
      this.advancedAttributes = new ArrayList<>();
    }
    return this.advancedAttributes;
  }

  /**
   * Assigns the SAML attributes.
   *
   * @param attributes the SAML attributes
   */
  public void setAttributes(final @Nullable List<AttributeInfo> attributes) {
    this.attributes = attributes;
  }

  /**
   * Assigns the SAML attributes (advanced, i.e., not displayed unless asked for).
   *
   * @param advancedAttributes the SAML attributes (advanced, i.e., not displayed unless asked for)
   */
  public void setAdvancedAttributes(final @Nullable List<AttributeInfo> advancedAttributes) {
    this.advancedAttributes = advancedAttributes;
  }

  /**
   * Gets the LoA URI.
   *
   * @return the LoA URI
   */
  public @Nullable String getLoaUri() {
    return this.loaUri;
  }

  /**
   * Assigns the LoA URI.
   *
   * @param loaUri the LoA URI
   */
  public void setLoaUri(final @Nullable String loaUri) {
    this.loaUri = loaUri;
  }

  /**
   * Gets the message code for level of assurance.
   *
   * @return the message code for level of assurance
   */
  public @Nullable String getLoaLevelMessageCode() {
    return this.loaLevelMessageCode;
  }

  /**
   * Assigns the message code for level of assurance.
   *
   * @param loaLevelMessageCode the message code for level of assurance
   */
  public void setLoaLevelMessageCode(final @Nullable String loaLevelMessageCode) {
    this.loaLevelMessageCode = loaLevelMessageCode;
  }

  /**
   * Gets the message code for a descriptive string for LoA.
   *
   * @return the message code for a descriptive string for LoA
   */
  public @Nullable String getLoaLevelDescriptionCode() {
    return this.loaLevelDescriptionCode;
  }

  /**
   * Assigns the message code for a descriptive string for LoA.
   *
   * @param loaLevelDescriptionCode the message code for a descriptive string for LoA
   */
  public void setLoaLevelDescriptionCode(final @Nullable String loaLevelDescriptionCode) {
    this.loaLevelDescriptionCode = loaLevelDescriptionCode;
  }

  /**
   * Gets the notified info message code.
   *
   * @return the notified info message code
   */
  public @Nullable String getNotifiedInfoMessageCode() {
    return this.notifiedInfoMessageCode;
  }

  /**
   * Assigns the notified info message code.
   *
   * @param notifiedInfoMessageCode the notified info message code
   */
  public void setNotifiedInfoMessageCode(final @Nullable String notifiedInfoMessageCode) {
    this.notifiedInfoMessageCode = notifiedInfoMessageCode;
  }

  /**
   * Tells whether the info holds information about an eIDAS assertion.
   *
   * @return {@code true} for an eIDAS assertion
   */
  public boolean isEidasAssertion() {
    return this.eidasAssertion;
  }

  /**
   * Assigns whether the info holds information about an eIDAS assertion.
   *
   * @param eidasAssertion whether this is an eIDAS assertion
   */
  public void setEidasAssertion(final boolean eidasAssertion) {
    this.eidasAssertion = eidasAssertion;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "AuthenticationInfo(attributes=" + this.attributes
        + ", advancedAttributes=" + this.advancedAttributes
        + ", loaUri=" + this.loaUri
        + ", loaLevelMessageCode=" + this.loaLevelMessageCode
        + ", loaLevelDescriptionCode=" + this.loaLevelDescriptionCode
        + ", notifiedInfoMessageCode=" + this.notifiedInfoMessageCode
        + ", eidasAssertion=" + this.eidasAssertion
        + ")";
  }

}
