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

import org.jspecify.annotations.Nullable;

/**
 * Model attribute for a SAML attribute.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class AttributeInfo {

  /** The message code for the attribute name. */
  private @Nullable String attributeNameCode;

  /** The attribute value. */
  private @Nullable String attributeValue;

  /** If the value is too long for the UI, we store only a part in the attributeValue property and the rest here. */
  private @Nullable String completeAttributeValue;

  /** The message code for the attribute info text. */
  private @Nullable String infoCode;

  /** Is this attribute "advanced"? I.e., should it be displayed under "Advanced"? */
  private boolean advanced;

  /** The sort order for attribute viewing. */
  private int sortOrder;

  /**
   * Gets the message code for the attribute name.
   *
   * @return the message code for the attribute name
   */
  public @Nullable String getAttributeNameCode() {
    return this.attributeNameCode;
  }

  /**
   * Assigns the message code for the attribute name.
   *
   * @param attributeNameCode the message code for the attribute name
   */
  public void setAttributeNameCode(final @Nullable String attributeNameCode) {
    this.attributeNameCode = attributeNameCode;
  }

  /**
   * Gets the attribute value.
   *
   * @return the attribute value
   */
  public @Nullable String getAttributeValue() {
    return this.attributeValue;
  }

  /**
   * Assigns the attribute value.
   *
   * @param attributeValue the attribute value
   */
  public void setAttributeValue(final @Nullable String attributeValue) {
    this.attributeValue = attributeValue;
  }

  /**
   * Gets the complete attribute value (if the value is too long for the UI).
   *
   * @return the complete attribute value
   */
  public @Nullable String getCompleteAttributeValue() {
    return this.completeAttributeValue;
  }

  /**
   * Assigns the complete attribute value.
   *
   * @param completeAttributeValue the complete attribute value
   */
  public void setCompleteAttributeValue(final @Nullable String completeAttributeValue) {
    this.completeAttributeValue = completeAttributeValue;
  }

  /**
   * Gets the message code for the attribute info text.
   *
   * @return the message code for the attribute info text
   */
  public @Nullable String getInfoCode() {
    return this.infoCode;
  }

  /**
   * Assigns the message code for the attribute info text.
   *
   * @param infoCode the message code for the attribute info text
   */
  public void setInfoCode(final @Nullable String infoCode) {
    this.infoCode = infoCode;
  }

  /**
   * Tells whether the attribute is "advanced", i.e., displayed under "Advanced".
   *
   * @return {@code true} if the attribute is advanced
   */
  public boolean isAdvanced() {
    return this.advanced;
  }

  /**
   * Assigns whether the attribute is "advanced", i.e., displayed under "Advanced".
   *
   * @param advanced whether the attribute is advanced
   */
  public void setAdvanced(final boolean advanced) {
    this.advanced = advanced;
  }

  /**
   * Gets the sort order for attribute viewing.
   *
   * @return the sort order for attribute viewing
   */
  public int getSortOrder() {
    return this.sortOrder;
  }

  /**
   * Assigns the sort order for attribute viewing.
   *
   * @param sortOrder the sort order for attribute viewing
   */
  public void setSortOrder(final int sortOrder) {
    this.sortOrder = sortOrder;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "AttributeInfo(attributeNameCode=" + this.attributeNameCode
        + ", attributeValue=" + this.attributeValue
        + ", completeAttributeValue=" + this.completeAttributeValue
        + ", infoCode=" + this.infoCode
        + ", advanced=" + this.advanced
        + ", sortOrder=" + this.sortOrder
        + ")";
  }

}
