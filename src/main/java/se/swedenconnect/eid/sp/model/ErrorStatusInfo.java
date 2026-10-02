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
import org.opensaml.saml.saml2.core.Status;


/**
 * Model class for representing a SAML error.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class ErrorStatusInfo {

  public static final @NonNull String CANCEL_CODE = "http://id.elegnamnden.se/status/1.0/cancel";

  private @Nullable String mainErrorCode;

  private @Nullable String subErrorCode;

  private @Nullable String errorMessage;

  /**
   * Constructor.
   *
   * @param status the SAML status
   */
  public ErrorStatusInfo(final @NonNull Status status) {
    this.mainErrorCode = status.getStatusCode().getValue();
    if (status.getStatusCode().getStatusCode() != null) {
      this.subErrorCode = status.getStatusCode().getStatusCode().getValue();
    }
    if (status.getStatusMessage() != null) {
      this.errorMessage = status.getStatusMessage().getValue();
    }
  }

  /**
   * Tells whether the status represents a user cancel.
   *
   * @return {@code true} if the user cancelled the operation
   */
  public boolean isCancel() {
    return CANCEL_CODE.equals(this.subErrorCode);
  }

  /**
   * Gets the main error code.
   *
   * @return the main error code
   */
  public @Nullable String getMainErrorCode() {
    return this.mainErrorCode;
  }

  /**
   * Assigns the main error code.
   *
   * @param mainErrorCode the main error code
   */
  public void setMainErrorCode(final @Nullable String mainErrorCode) {
    this.mainErrorCode = mainErrorCode;
  }

  /**
   * Gets the sub error code.
   *
   * @return the sub error code
   */
  public @Nullable String getSubErrorCode() {
    return this.subErrorCode;
  }

  /**
   * Assigns the sub error code.
   *
   * @param subErrorCode the sub error code
   */
  public void setSubErrorCode(final @Nullable String subErrorCode) {
    this.subErrorCode = subErrorCode;
  }

  /**
   * Gets the error message.
   *
   * @return the error message
   */
  public @Nullable String getErrorMessage() {
    return this.errorMessage;
  }

  /**
   * Assigns the error message.
   *
   * @param errorMessage the error message
   */
  public void setErrorMessage(final @Nullable String errorMessage) {
    this.errorMessage = errorMessage;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "ErrorStatusInfo(mainErrorCode=" + this.mainErrorCode
        + ", subErrorCode=" + this.subErrorCode
        + ", errorMessage=" + this.errorMessage
        + ")";
  }

}
