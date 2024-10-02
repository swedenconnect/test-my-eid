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

import org.opensaml.saml.saml2.core.Status;

import lombok.Data;
import lombok.ToString;

/**
 * Model class for representing a SAML error.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Data
@ToString
public class ErrorStatusInfo {

  public static final String CANCEL_CODE = "http://id.elegnamnden.se/status/1.0/cancel";

  private String mainErrorCode;

  private String subErrorCode;

  private String errorMessage;

  public ErrorStatusInfo(final Status status) {
    this.mainErrorCode = status.getStatusCode().getValue();
    if (status.getStatusCode().getStatusCode() != null) {
      this.subErrorCode = status.getStatusCode().getStatusCode().getValue();
    }
    if (status.getStatusMessage() != null) {
      this.errorMessage = status.getStatusMessage().getValue();
    }
  }

  public boolean isCancel() {
    return this.subErrorCode != null && CANCEL_CODE.equals(this.subErrorCode);
  }

}
