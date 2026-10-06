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
import se.oidc.nimbus.claims.ClaimConstants;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;
import java.util.Objects;

/**
 * A successful OIDC authentication, kept in the user's session so that a signature approval can be bound to it (the
 * OIDC counterpart of {@code last-authentication} on the SAML side).
 *
 * @param issuer the issuer of the OP
 * @param personalIdentityNumber the personal identity number (may be {@code null})
 * @param coordinationNumber the coordination number (may be {@code null})
 * @param givenName the given name (may be {@code null})
 * @param acr the {@code acr} from the ID token (may be {@code null})
 * @author Martin Lindström
 */
public record OidcAuthentication(
    @NonNull String issuer,
    @Nullable String personalIdentityNumber,
    @Nullable String coordinationNumber,
    @Nullable String givenName,
    @Nullable String acr) implements Serializable {

  /** The session attribute name. */
  public static final @NonNull String SESSION_ATTRIBUTE = "oidc-last-authentication";

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * Creates the authentication from the result of a processed response.
   *
   * @param result the result
   * @return an {@link OidcAuthentication}
   */
  public static @NonNull OidcAuthentication from(final @NonNull OidcAuthenticationResult result) {
    final Map<String, Object> claims = result.getClaims();
    return new OidcAuthentication(result.getIssuer(),
        stringClaim(claims, ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME),
        stringClaim(claims, ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME),
        stringClaim(claims, "given_name"),
        result.getAcr());
  }

  /**
   * Tells whether the identity in the result is the same as in this authentication. The personal identity number is
   * compared, or the coordination number when that was what the authentication delivered.
   *
   * @param result the result to compare with
   * @return {@code true} if the identities match
   */
  public boolean isIdentityMatch(final @NonNull OidcAuthenticationResult result) {
    if (this.personalIdentityNumber != null) {
      return this.personalIdentityNumber.equals(
          stringClaim(result.getClaims(), ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME));
    }
    if (this.coordinationNumber != null) {
      return this.coordinationNumber.equals(
          stringClaim(result.getClaims(), ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME));
    }
    return false;
  }

  /**
   * Gets a claim as a string.
   *
   * @param claims the claims
   * @param name the claim name
   * @return the value, or {@code null}
   */
  private static @Nullable String stringClaim(final @NonNull Map<String, Object> claims, final @NonNull String name) {
    return Objects.toString(claims.get(name), null);
  }

}
