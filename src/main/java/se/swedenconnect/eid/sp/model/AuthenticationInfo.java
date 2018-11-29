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

import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Model class for the information to display about an authentication.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@ToString
public class AuthenticationInfo {

  /** The SAML attributes. */
  @Setter
  private List<AttributeInfo> attributes;

  /** The SAML attributes (advanced, i.e., not displayed unless asked for). */
  @Setter
  private List<AttributeInfo> advancedAttributes;

  /** The message code for level of assurance. */
  @Setter
  @Getter
  private String loaLevelMessageCode;
  
  /** The message code for a descriptive string for LoA. */
  @Setter
  @Getter
  private String loaLevelDescriptionCode;

  /** Message code for notified/non-notified text (eIDAS only). */
  @Setter
  @Getter
  private String notifiedInfoMessageCode;
  
  /** Flag telling whether the info holds information about an eIDAS assertion or not. */
  @Setter
  @Getter
  private boolean eidasAssertion = false;

  public List<AttributeInfo> getAttributes() {
    if (this.attributes == null) {
      this.attributes = new ArrayList<>();
    }
    return this.attributes;
  }

  public List<AttributeInfo> getAdvancedAttributes() {
    if (this.advancedAttributes == null) {
      this.advancedAttributes = new ArrayList<>();
    }
    return this.advancedAttributes;
  }

}
