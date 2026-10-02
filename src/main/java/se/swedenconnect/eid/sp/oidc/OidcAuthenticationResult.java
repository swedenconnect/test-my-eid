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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The result of a successfully processed OIDC authentication response: the validated ID token and UserInfo claims.
 *
 * @author Martin Lindström
 */
public class OidcAuthenticationResult {

  /** The issuer of the OP. */
  private final @NonNull String issuer;

  /** The {@code sub} claim. */
  private final @NonNull String subject;

  /** The {@code acr} claim from the ID token. */
  private final @Nullable String acr;

  /** The claims from the ID token and UserInfo, merged (UserInfo values win). */
  private final @NonNull Map<String, Object> claims;

  /**
   * Constructor.
   *
   * @param issuer the issuer of the OP
   * @param subject the {@code sub} claim
   * @param acr the {@code acr} claim
   * @param idTokenClaims the ID token claims
   * @param userInfoClaims the UserInfo claims
   */
  public OidcAuthenticationResult(final @NonNull String issuer, final @NonNull String subject,
      final @Nullable String acr, final @NonNull Map<String, Object> idTokenClaims,
      final @NonNull Map<String, Object> userInfoClaims) {
    this.issuer = issuer;
    this.subject = subject;
    this.acr = acr;
    final Map<String, Object> merged = new LinkedHashMap<>(idTokenClaims);
    merged.putAll(userInfoClaims);
    this.claims = Collections.unmodifiableMap(merged);
  }

  /**
   * Gets the merged claims from the ID token and UserInfo.
   *
   * @return the claims
   */
  public @NonNull Map<String, Object> getClaims() {
    return this.claims;
  }

  /**
   * Gets the issuer of the OP.
   *
   * @return the issuer of the OP
   */
  public @NonNull String getIssuer() {
    return this.issuer;
  }

  /**
   * Gets the {@code sub} claim.
   *
   * @return the {@code sub} claim
   */
  public @NonNull String getSubject() {
    return this.subject;
  }

  /**
   * Gets the {@code acr} claim from the ID token.
   *
   * @return the {@code acr} claim from the ID token
   */
  public @Nullable String getAcr() {
    return this.acr;
  }

}
