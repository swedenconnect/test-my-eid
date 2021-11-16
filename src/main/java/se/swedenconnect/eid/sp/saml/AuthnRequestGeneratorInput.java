/*
 * Copyright 2018-2021 Sweden Connect
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

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.opensaml.saml2.request.AbstractAuthnRequestGeneratorInput;

/**
 * Input for generating {@code AuthnRequest} messages.
 * 
 * @author Martin Lindström (martin@idsec.se)
 */
public class AuthnRequestGeneratorInput extends AbstractAuthnRequestGeneratorInput {
  
  @Getter
  @Setter
  private boolean debug;
  
  @Getter
  @Setter
  private String country;
  
  @Getter
  @Setter
  private boolean ping;
  
  @Getter
  @Setter
  private String signMessage;
  
  @Getter
  @Setter
  private String personalIdentityNumberHint;
  
  @Getter
  @Setter
  private String pridHint;
  
  @Getter
  @Setter
  private String requestedAuthnContextUri;
  
  public AuthnRequestGeneratorInput(final String idpEntityID) {
    this.setPeerEntityID(idpEntityID);
  }

}
