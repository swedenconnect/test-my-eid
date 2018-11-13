/*
 * Copyright 2018 Sweden Connect
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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import lombok.Data;
import lombok.Setter;
import lombok.ToString;
import se.litsec.opensaml.saml2.attribute.AttributeUtils;

/**
 * Registry holding information about attributes. This information is used when a listing of received attributes are
 * displayed.
 * 
 * @author Martin Lindström (martin@litsec.se)
 */
@Component
@ConfigurationProperties(prefix = "sp.ui")
public class AttributeInfoRegistry {

  /** Max length for attributes being displayed. */
  public static final int MAX_ATTR_DISPLAY_LENGTH = 25;

  /** A list of attribute info model objects. */
  @Setter
  private List<AttrInfo> attributes;

  /**
   * Resolves the supplied SAML attribute into an attribute info model object.
   * 
   * @param attribute
   *          the SAML attribute to resolve
   * @param eidasFlag
   *          a flag telling whether we process an eIDAS assertion
   * @return the attribute model
   */
  public AttributeInfo resolve(Attribute attribute, boolean eidasFlag) {
    final String name = attribute.getName();
    for (int i = 0; i < this.attributes.size(); i++) {
      final AttrInfo ai = this.attributes.get(i);
      if (ai.getAttributeName().equals(name)) {
        AttributeInfo attributeInfo = new AttributeInfo();
        attributeInfo.setAttributeNameCode(ai.getMessageCode(eidasFlag));
        attributeInfo.setAttributeValue(AttributeUtils.getAttributeStringValue(attribute));
        attributeInfo.setInfoCode(ai.getDescriptionMessageCode(eidasFlag));
        attributeInfo.setAdvanced(ai.isAdvanced());
        attributeInfo.setSortOrder(i);
        
        return attributeInfo;
      }
    }
    return null;
  }

  /**
   * Attribute info model class.
   */
  @Data
  @ToString
  public static class AttrInfo {

    /** The name of the attribute. */
    private String attributeName;

    /** The message code for the attribute. */
    private String messageCode;

    /** The message code the attribute if eIDAS is used. If {@code null}, the value for {@code messageCode} is used. */
    private String messageCodeEidas;

    /** The message code for the attribute description. */
    private String descriptionMessageCode;

    /** The message code the for attribute description in eIDAS context. */
    private String descriptionMessageCodeEidas;

    /** Flag telling whether this attribute is "advanced" (to be displayed under the advanced section). */
    private boolean advanced;

    /**
     * Returns the message code for the attribute.
     * 
     * @param eidasFlag
     *          is eIDAS used?
     * @return the message code to use for the attribute
     */
    public String getMessageCode(boolean eidasFlag) {
      return eidasFlag && StringUtils.hasText(this.messageCodeEidas) ? this.messageCodeEidas : this.messageCode;
    }

    /**
     * Returns the message code for the description field.
     * 
     * @param eidasFlag
     *          is eIDAS used?
     * @return the message code for the description field
     */
    public String getDescriptionMessageCode(boolean eidasFlag) {
      return eidasFlag ? this.descriptionMessageCodeEidas : descriptionMessageCode;
    }
  }

}
