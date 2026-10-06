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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Processes a successful OIDC authorization response: exchanges the code at the token endpoint (authenticating with
 * {@code private_key_jwt} and PKCE), validates the ID token, calls UserInfo and validates its signed response.
 *
 * @author Martin Lindström
 */
public class OidcResponseProcessor {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcResponseProcessor.class);

  /** HTTP timeout. */
  private static final int HTTP_TIMEOUT_MILLIS = 10_000;

  /** Size limit for downloaded JWK sets. */
  private static final int JWKS_SIZE_LIMIT = 256 * 1024;

  /** The lifetime of a client assertion. */
  private static final Duration CLIENT_ASSERTION_LIFETIME = Duration.ofMinutes(1);

  /** The Relying Party. */
  private final @NonNull RelyingParty relyingParty;

  /** The clock. */
  private final @NonNull Clock clock;

  /** Cached key sources for OP keys published at {@code jwks_uri}, where the key is the URI. */
  private final @NonNull Map<String, JWKSource<SecurityContext>> keySources = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param relyingParty the Relying Party
   * @param clock the clock
   */
  public OidcResponseProcessor(final @NonNull RelyingParty relyingParty, final @NonNull Clock clock) {
    this.relyingParty = Objects.requireNonNull(relyingParty, "relyingParty must be set");
    this.clock = Objects.requireNonNull(clock, "clock must be set");
  }

  /**
   * Processes the authorization code.
   *
   * @param op the OP
   * @param code the authorization code
   * @param state the request state
   * @return the result
   * @throws OidcResponseException if the processing or validation fails
   */
  public @NonNull OidcAuthenticationResult process(final @NonNull OpenIdProvider op, final @NonNull String code,
      final @NonNull OidcRequestState state) throws OidcResponseException {

    final OIDCTokenResponse tokenResponse = this.requestToken(op, code, state);
    final JWT idToken = tokenResponse.getOIDCTokens().getIDToken();
    if (idToken == null) {
      throw new OidcResponseException("No ID token in token response");
    }
    final IDTokenClaimsSet idTokenClaims = this.validateIdToken(op, idToken, state);
    final String acr = idTokenClaims.getACR() != null ? idTokenClaims.getACR().getValue() : null;

    final JWTClaimsSet userInfoClaims =
        this.getUserInfo(op, tokenResponse.getOIDCTokens().getAccessToken(), idTokenClaims.getSubject().getValue());

    log.debug("Processed OIDC response from '{}' [sub='{}', acr='{}']",
        op.getIssuer(), idTokenClaims.getSubject(), acr);

    return new OidcAuthenticationResult(op.getIssuer(), idTokenClaims.getSubject().getValue(), acr,
        idTokenClaims.toJSONObject(), userInfoClaims.toJSONObject());
  }

  /**
   * Exchanges the code at the token endpoint.
   *
   * @param op the OP
   * @param code the code
   * @param state the request state
   * @return the token response
   * @throws OidcResponseException for errors
   */
  private @NonNull OIDCTokenResponse requestToken(final @NonNull OpenIdProvider op, final @NonNull String code,
      final @NonNull OidcRequestState state) throws OidcResponseException {
    final URI tokenEndpoint = op.getMetadata().getTokenEndpointURI();
    if (tokenEndpoint == null) {
      throw new OidcResponseException("OP '%s' has no token endpoint".formatted(op.getIssuer()));
    }
    try {
      final TokenRequest request = new TokenRequest(tokenEndpoint, this.clientAssertion(tokenEndpoint),
          new AuthorizationCodeGrant(new AuthorizationCode(code), this.relyingParty.getRedirectUri(),
              new CodeVerifier(state.codeVerifier())));
      final HTTPRequest httpRequest = request.toHTTPRequest();
      httpRequest.setConnectTimeout(HTTP_TIMEOUT_MILLIS);
      httpRequest.setReadTimeout(HTTP_TIMEOUT_MILLIS);
      final TokenResponse response = OIDCTokenResponseParser.parse(httpRequest.send());
      if (!response.indicatesSuccess()) {
        final TokenErrorResponse error = response.toErrorResponse();
        throw new OidcResponseException("Token request failed - %s: %s".formatted(
            error.getErrorObject().getCode(), error.getErrorObject().getDescription()));
      }
      if (!(response instanceof final OIDCTokenResponse oidcResponse)) {
        throw new OidcResponseException("Token response is not an OpenID Connect token response");
      }
      return oidcResponse;
    }
    catch (final IOException | ParseException e) {
      throw new OidcResponseException("Token request failed - " + e.getMessage(), e);
    }
  }

  /**
   * Creates a {@code private_key_jwt} client assertion with the token endpoint as audience.
   *
   * @param tokenEndpoint the token endpoint
   * @return the client authentication
   * @throws OidcResponseException for signing errors
   */
  private @NonNull PrivateKeyJWT clientAssertion(final @NonNull URI tokenEndpoint) throws OidcResponseException {
    try {
      final Instant now = this.clock.instant();
      final JWTAuthenticationClaimsSet claims = new JWTAuthenticationClaimsSet(
          new Issuer(this.relyingParty.getClientId().getValue()), this.relyingParty.getClientId(),
          new Audience(tokenEndpoint.toString()).toSingleAudienceList(),
          Date.from(now.plus(CLIENT_ASSERTION_LIFETIME)), null, Date.from(now), new JWTID());
      final JWSHeader header = new JWSHeader.Builder(this.relyingParty.getSignatureAlgorithm())
          .keyID(this.relyingParty.getSignJwk().getKeyID())
          .build();
      final SignedJWT jwt = new SignedJWT(header, claims.toJWTClaimsSet());
      jwt.sign(JoseSupport.signer(this.relyingParty.getSignCredential()));
      return new PrivateKeyJWT(jwt);
    }
    catch (final JOSEException e) {
      throw new OidcResponseException("Failed to sign client assertion - " + e.getMessage(), e);
    }
  }

  /**
   * Validates the ID token as OpenID Connect Core, Section 3.1.3.7, requires.
   *
   * @param op the OP
   * @param idToken the ID token
   * @param state the request state
   * @return the validated claims
   * @throws OidcResponseException if validation fails
   */
  private @NonNull IDTokenClaimsSet validateIdToken(final @NonNull OpenIdProvider op, final @NonNull JWT idToken,
      final @NonNull OidcRequestState state) throws OidcResponseException {
    final SignedJWT signedIdToken = this.decryptIfRequired(idToken, "ID token",
        this.relyingParty.getMetadata().getIDTokenJWEAlg(), this.relyingParty.getMetadata().getIDTokenJWEEnc());
    try {
      final IDTokenValidator validator = new IDTokenValidator(new Issuer(op.getIssuer()),
          this.relyingParty.getClientId(), this.keySelector(op), null);
      final IDTokenClaimsSet claims = validator.validate(signedIdToken, new Nonce(state.nonce()));
      if (claims.getAuthenticationTime() == null) {
        throw new OidcResponseException("ID token has no auth_time claim");
      }
      return claims;
    }
    catch (final BadJOSEException | JOSEException e) {
      throw new OidcResponseException("Invalid ID token - " + e.getMessage(), e);
    }
  }

  /**
   * Calls UserInfo with the access token and validates the response, which must be signed (and encrypted when
   * encryption is turned on), as OpenID Connect Core, Section 5.3.4, requires.
   *
   * @param op the OP
   * @param accessToken the access token
   * @param subject the {@code sub} of the ID token
   * @return the UserInfo claims
   * @throws OidcResponseException if the call or validation fails
   */
  private @NonNull JWTClaimsSet getUserInfo(final @NonNull OpenIdProvider op, final @NonNull AccessToken accessToken,
      final @NonNull String subject) throws OidcResponseException {
    final URI endpoint = op.getMetadata().getUserInfoEndpointURI();
    if (endpoint == null) {
      throw new OidcResponseException("OP '%s' has no UserInfo endpoint".formatted(op.getIssuer()));
    }
    final HTTPResponse response;
    try {
      final HTTPRequest httpRequest = new UserInfoRequest(endpoint, accessToken).toHTTPRequest();
      httpRequest.setConnectTimeout(HTTP_TIMEOUT_MILLIS);
      httpRequest.setReadTimeout(HTTP_TIMEOUT_MILLIS);
      response = httpRequest.send();
    }
    catch (final IOException e) {
      throw new OidcResponseException("UserInfo request failed - " + e.getMessage(), e);
    }
    if (response.getStatusCode() != HTTPResponse.SC_OK) {
      throw new OidcResponseException("UserInfo request failed - HTTP status %d".formatted(response.getStatusCode()));
    }
    if (response.getEntityContentType() == null
        || !response.getEntityContentType().matches(com.nimbusds.common.contenttype.ContentType.APPLICATION_JWT)) {
      throw new OidcResponseException("UserInfo response is not signed (content type '%s')"
          .formatted(response.getHeaderValue("Content-Type")));
    }
    final JWT jwt;
    try {
      jwt = JWTParser.parse(response.getBody().trim());
    }
    catch (final java.text.ParseException e) {
      throw new OidcResponseException("Invalid UserInfo response - " + e.getMessage(), e);
    }
    final SignedJWT signed = this.decryptIfRequired(jwt, "UserInfo response",
        this.relyingParty.getMetadata().getUserInfoJWEAlg(), this.relyingParty.getMetadata().getUserInfoJWEEnc());

    final JWTClaimsSet claims;
    try {
      final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
      processor.setJWSKeySelector(this.keySelector(op));
      processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(null, Set.of("sub")));
      claims = processor.process(signed, null);
    }
    catch (final BadJOSEException | JOSEException e) {
      throw new OidcResponseException("Invalid UserInfo response - " + e.getMessage(), e);
    }
    if (!subject.equals(claims.getSubject())) {
      throw new OidcResponseException("UserInfo sub '%s' does not equal ID token sub '%s'"
          .formatted(claims.getSubject(), subject));
    }
    if (claims.getIssuer() != null && !op.getIssuer().equals(claims.getIssuer())) {
      throw new OidcResponseException("UserInfo iss '%s' does not equal issuer '%s'"
          .formatted(claims.getIssuer(), op.getIssuer()));
    }
    final List<String> audience = claims.getAudience();
    if (audience != null && !audience.isEmpty()
        && !audience.contains(this.relyingParty.getClientId().getValue())) {
      throw new OidcResponseException("UserInfo aud %s does not contain client ID".formatted(audience));
    }
    return claims;
  }

  /**
   * Returns the signed JWT, after decrypting it when encryption is turned on. When encryption is on the JWT must be
   * encrypted with the declared algorithms, and when it is off it must not be encrypted.
   *
   * @param jwt the JWT
   * @param what what the JWT is (for error messages)
   * @param alg the declared key management algorithm (null when encryption is off)
   * @param enc the declared content encryption algorithm (null when encryption is off)
   * @return the signed JWT
   * @throws OidcResponseException for errors
   */
  private @NonNull SignedJWT decryptIfRequired(final @NonNull JWT jwt, final @NonNull String what,
      final @Nullable JWEAlgorithm alg, final @Nullable EncryptionMethod enc) throws OidcResponseException {
    if (this.relyingParty.isEncryptionEnabled()) {
      if (!(jwt instanceof final EncryptedJWT encrypted)) {
        throw new OidcResponseException("%s is not encrypted".formatted(what));
      }
      if (!Objects.equals(alg, encrypted.getHeader().getAlgorithm())
          || !Objects.equals(enc, encrypted.getHeader().getEncryptionMethod())) {
        throw new OidcResponseException("%s is encrypted with %s/%s - expected %s/%s".formatted(what,
            encrypted.getHeader().getAlgorithm(), encrypted.getHeader().getEncryptionMethod(), alg, enc));
      }
      try {
        encrypted.decrypt(JoseSupport.decrypter(Objects.requireNonNull(this.relyingParty.getDecryptCredential())));
      }
      catch (final JOSEException e) {
        throw new OidcResponseException("Failed to decrypt %s - %s".formatted(what, e.getMessage()), e);
      }
      final SignedJWT nested = encrypted.getPayload().toSignedJWT();
      if (nested == null) {
        throw new OidcResponseException("Encrypted %s does not hold a signed JWT".formatted(what));
      }
      return nested;
    }
    if (jwt instanceof final SignedJWT signed) {
      return signed;
    }
    throw new OidcResponseException("%s is not a signed JWT".formatted(what));
  }

  /**
   * Gets a key selector for the OP's signature keys that only accepts the algorithms that the Sweden Connect security
   * requirements allow.
   *
   * @param op the OP
   * @return a key selector
   * @throws OidcResponseException if the OP has no keys
   */
  private @NonNull JWSVerificationKeySelector<SecurityContext> keySelector(final @NonNull OpenIdProvider op)
      throws OidcResponseException {
    return new JWSVerificationKeySelector<>(JoseSupport.ALLOWED_SIGNATURE_ALGORITHMS, this.keySource(op));
  }

  /**
   * Gets the key source for the OP's keys: the {@code jwks} of its metadata, or else its {@code jwks_uri}.
   *
   * @param op the OP
   * @return a key source
   * @throws OidcResponseException if the OP has no keys
   */
  private @NonNull JWKSource<SecurityContext> keySource(final @NonNull OpenIdProvider op)
      throws OidcResponseException {
    final Object jwks = op.getDocument().get("jwks");
    if (jwks instanceof final Map<?, ?> map) {
      try {
        @SuppressWarnings("unchecked")
        final JWKSet set = JWKSet.parse((Map<String, Object>) map);
        return new ImmutableJWKSet<>(set);
      }
      catch (final java.text.ParseException e) {
        throw new OidcResponseException("Invalid jwks in metadata for OP '%s'".formatted(op.getIssuer()), e);
      }
    }
    final URI jwksUri = op.getMetadata().getJWKSetURI();
    if (jwksUri == null) {
      throw new OidcResponseException("OP '%s' has no keys (jwks or jwks_uri)".formatted(op.getIssuer()));
    }
    return this.keySources.computeIfAbsent(jwksUri.toString(), u -> {
      try {
        final URL url = jwksUri.toURL();
        return JWKSourceBuilder.<SecurityContext>create(url,
                new DefaultResourceRetriever(HTTP_TIMEOUT_MILLIS, HTTP_TIMEOUT_MILLIS, JWKS_SIZE_LIMIT))
            .retrying(true)
            .build();
      }
      catch (final IOException e) {
        throw new IllegalArgumentException("Invalid jwks_uri " + u, e);
      }
    });
  }

  /**
   * Exception for errors processing an OIDC response.
   */
  public static class OidcResponseException extends Exception {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructor.
     *
     * @param message the error message
     */
    public OidcResponseException(final @NonNull String message) {
      super(message);
    }

    /**
     * Constructor.
     *
     * @param message the error message
     * @param cause the cause
     */
    public OidcResponseException(final @NonNull String message, final @NonNull Throwable cause) {
      super(message, cause);
    }
  }

}
