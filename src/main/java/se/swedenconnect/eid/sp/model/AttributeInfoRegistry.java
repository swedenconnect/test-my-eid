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

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.eid.sp.config.SpConfigurationProperties.UiConfiguration.AttributeConfig;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;

/**
 * Registry holding information about attributes. This information is used when a listing of received attributes are
 * displayed.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class AttributeInfoRegistry {

  /** Max length for attributes being displayed. */
  public static final int MAX_ATTR_DISPLAY_LENGTH = 25;

  /** A list of attribute info model objects. */
  private final List<AttributeConfig> attributes;

  /**
   * Constructor.
   *
   * @param attributes the attribute configuration
   */
  public AttributeInfoRegistry(final @NonNull List<AttributeConfig> attributes) {
    this.attributes = Objects.requireNonNull(attributes, "attributes must not be null");
  }

  /**
   * Resolves the supplied SAML attribute into an attribute info model object.
   *
   * @param attribute the SAML attribute to resolve
   * @param eidasFlag a flag telling whether we process an eIDAS assertion
   * @return the attribute model
   */
  public @Nullable AttributeInfo resolve(final @NonNull Attribute attribute, final boolean eidasFlag) {
    return this.resolve(attribute.getName(), AttributeUtils.getAttributeStringValue(attribute), eidasFlag);
  }

  /**
   * Resolves the supplied attribute name and value into an attribute info model object.
   *
   * @param attributeName the attribute name
   * @param attributeValue the attribute value
   * @param eidasFlag a flag telling whether we process an eIDAS assertion
   * @return the attribute model, or {@code null} if the attribute is not configured
   */
  public @Nullable AttributeInfo resolve(
      final @NonNull String attributeName, final @Nullable String attributeValue, final boolean eidasFlag) {
    for (int i = 0; i < this.attributes.size(); i++) {
      final AttributeConfig ai = this.attributes.get(i);
      if (attributeName.equals(ai.getAttributeName())) {
        final AttributeInfo attributeInfo = new AttributeInfo();
        attributeInfo.setAttributeNameCode(ai.getMessageCode(eidasFlag));
        attributeInfo.setAttributeValue(attributeValue);
        attributeInfo.setInfoCode(ai.getDescriptionMessageCode(eidasFlag));
        attributeInfo.setAdvanced(ai.isAdvanced());
        attributeInfo.setSortOrder(i);

        return attributeInfo;
      }
    }
    return null;
  }


  /**
   * Resolves an OpenID Connect claim into an {@link AttributeInfo} using the label of the attribute that is configured
   * with the claim name.
   *
   * @param claimName the claim name
   * @param claimValue the claim value (as a string)
   * @return an {@link AttributeInfo}, or {@code null} if no label is configured for the claim
   */
  public @Nullable AttributeInfo resolveClaim(final @NonNull String claimName, final @Nullable String claimValue) {
    for (int i = 0; i < this.attributes.size(); i++) {
      final AttributeConfig ai = this.attributes.get(i);
      if (claimName.equals(ai.getClaimName())) {
        final AttributeInfo attributeInfo = new AttributeInfo();
        attributeInfo.setAttributeNameCode(ai.getMessageCode(false));
        attributeInfo.setAttributeValue(claimValue);
        attributeInfo.setInfoCode(ai.getDescriptionMessageCode(false));
        attributeInfo.setAdvanced(ai.isAdvanced());
        attributeInfo.setSortOrder(i);
        return attributeInfo;
      }
    }
    return null;
  }

}
