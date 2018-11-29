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

import lombok.Data;
import lombok.ToString;

/**
 * Model attribute for a SAML attribute.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Data
@ToString
public class AttributeInfo {

  /** The message code for the attribute name. */
  private String attributeNameCode;

  /** The attribute value. */
  private String attributeValue;

  /** If the value is too long for the UI, we store only a part in the attributeValue property and the rest here. */
  private String completeAttributeValue;

  /** The message code for the attribute info text. */
  private String infoCode;

  /** Is this attribute "advanced"? I.e., should it be displayed under "Advanced"? */
  private boolean advanced;

  /** The sort order for attribute viewing. */
  private int sortOrder;

}
