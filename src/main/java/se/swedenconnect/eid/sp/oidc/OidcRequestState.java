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
package se.swedenconnect.eid.sp.oidc;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.Serial;
import java.io.Serializable;

/**
 * The state of a sent OIDC authentication request, kept in the user's session until the response arrives.
 *
 * @param issuer the issuer of the OP the request was sent to
 * @param state the {@code state} parameter
 * @param nonce the {@code nonce} parameter
 * @param codeVerifier the PKCE code verifier
 * @param signMessage the sign message for a signature approval request ({@code null} for authentication)
 * @param expectedIdentity the authentication that a signature approval must match ({@code null} for
 *     authentication)
 * @author Martin Lindström
 */
public record OidcRequestState(
    @NonNull String issuer,
    @NonNull String state,
    @NonNull String nonce,
    @NonNull String codeVerifier,
    @Nullable String signMessage,
    @Nullable OidcAuthentication expectedIdentity) implements Serializable {

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * Tells whether this is a signature approval request.
   *
   * @return {@code true} for signature approval
   */
  public boolean isSignatureApproval() {
    return this.signMessage != null;
  }

}
