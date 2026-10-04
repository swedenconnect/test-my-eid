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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.oidc.nimbus.claims.ClaimConstants;
import se.oidc.nimbus.claims.ParameterConstants;
import se.oidc.nimbus.claims.ScopeConstants;
import se.oidc.nimbus.usermessage.UserMessage;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Creates OIDC authentication requests. All parameters are carried in a signed Request Object passed by value. The
 * parameters that OpenID Connect Core requires outside the Request Object are also sent as plain parameters.
 *
 * @author Martin Lindström
 */
public class OidcRequestFactory {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcRequestFactory.class);

  /**
   * The scope for the signature approval use case (Signature Extension for OpenID Connect 1.1). Not defined by
   * oidc-sweden-nimbus, whose {@code ScopeConstants.SIGN} is the {@code sign} scope of version 1.0.
   */
  public static final @NonNull String SIGN_APPROVAL_SCOPE = "https://id.oidc.se/scope/signApproval";

  /** The lifetime of a Request Object. */
  private static final Duration REQUEST_OBJECT_LIFETIME = Duration.ofMinutes(5);

  /** The Relying Party. */
  private final @NonNull RelyingParty relyingParty;

  /** Markdown user message templates, where the key is the language tag. */
  private final @NonNull Map<String, String> markdownUserMessages;

  /** Plain-text user message templates, where the key is the language tag. */
  private final @NonNull Map<String, String> plainUserMessages;

  /** The clock. */
  private final @NonNull Clock clock;

  /**
   * Constructor.
   *
   * @param relyingParty the Relying Party
   * @param markdownUserMessages Markdown user message templates
   * @param plainUserMessages plain-text user message templates
   * @param clock the clock
   */
  public OidcRequestFactory(final @NonNull RelyingParty relyingParty,
      final @NonNull Map<String, String> markdownUserMessages, final @NonNull Map<String, String> plainUserMessages,
      final @NonNull Clock clock) {
    this.relyingParty = Objects.requireNonNull(relyingParty, "relyingParty must be set");
    this.markdownUserMessages = Objects.requireNonNull(markdownUserMessages, "markdownUserMessages must be set");
    this.plainUserMessages = Objects.requireNonNull(plainUserMessages, "plainUserMessages must be set");
    this.clock = Objects.requireNonNull(clock, "clock must be set");
  }

  /**
   * Creates an authentication request.
   *
   * @param op the OP
   * @return the request
   */
  public @NonNull OidcRequest createAuthenticationRequest(final @NonNull OpenIdProvider op) {
    final Scope scope = this.identityScopes(op);
    final JWTClaimsSet.Builder claims = this.commonClaims(op, scope);
    claims.claim("prompt", "login");
    final List<String> acrValues = op.getStringList("acr_values_supported");
    if (!acrValues.isEmpty()) {
      claims.claim("acr_values", String.join(" ", acrValues));
    }
    return this.createRequest(op, scope, claims, null, null);
  }

  /**
   * Creates a signature approval request bound to the given authentication.
   *
   * @param op the OP
   * @param authentication the authentication the signature approval is bound to
   * @param signMessage the sign message (plain text)
   * @return the request
   */
  public @NonNull OidcRequest createSignatureApprovalRequest(final @NonNull OpenIdProvider op,
      final @NonNull OidcAuthentication authentication, final @NonNull String signMessage) {
    final Scope scope = new Scope(OIDCScopeValue.OPENID);
    scope.add(SIGN_APPROVAL_SCOPE);
    this.identityScopes(op).stream().filter(s -> !scope.contains(s)).forEach(scope::add);

    final JWTClaimsSet.Builder claims = this.commonClaims(op, scope);
    claims.claim("prompt", "login consent");

    // The signature approval use case has a sign_message but no tbs_data. The SignRequest class of
    // oidc-sweden-nimbus requires tbs_data, so the parameter is built here.
    final JSONObject signRequest = new JSONObject();
    signRequest.put("sign_message", encode(
        new UserMessage(List.of(new UserMessage.Message(signMessage)), UserMessage.TEXT_MIME_TYPE)));
    claims.claim(ParameterConstants.SIGN_REQUEST_PARAM_NAME, signRequest);

    // Bind the request to the authenticated user
    final JSONObject idToken = new JSONObject();
    if (authentication.personalIdentityNumber() != null) {
      idToken.put(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME,
          essential(authentication.personalIdentityNumber()));
    }
    else if (authentication.coordinationNumber() != null) {
      idToken.put(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME, essential(authentication.coordinationNumber()));
    }
    if (authentication.acr() != null) {
      idToken.put("acr", essential(authentication.acr()));
    }
    final JSONObject claimsParameter = new JSONObject();
    claimsParameter.put("id_token", idToken);
    claims.claim("claims", claimsParameter);

    return this.createRequest(op, scope, claims, signMessage, authentication);
  }

  /**
   * Gets {@code openid} plus the identity scopes that the OP lists in {@code scopes_supported}.
   *
   * @param op the OP
   * @return the scope
   */
  private @NonNull Scope identityScopes(final @NonNull OpenIdProvider op) {
    final Scope scope = new Scope(OIDCScopeValue.OPENID);
    for (final String s : List.of(ScopeConstants.NATURAL_PERSON_INFO.getValue(),
        ScopeConstants.NATURAL_PERSON_PERSONAL_NUMBER.getValue())) {
      if (op.supportsScope(s)) {
        scope.add(s);
      }
    }
    return scope;
  }

  /**
   * Creates the claims common to all Request Objects (the parts that do not depend on the request type).
   *
   * @param op the OP
   * @param scope the scope
   * @return a claims builder
   */
  private JWTClaimsSet.@NonNull Builder commonClaims(final @NonNull OpenIdProvider op, final @NonNull Scope scope) {
    final Instant now = this.clock.instant();
    final String clientId = this.relyingParty.getClientId().getValue();
    return new JWTClaimsSet.Builder()
        .issuer(clientId)
        // The OP's entity identifier, and no other value (OpenID Federation, Section 12.1.1.1)
        .audience(op.getEntityId())
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plus(REQUEST_OBJECT_LIFETIME)))
        .jwtID(UUID.randomUUID().toString())
        .claim("client_id", clientId)
        .claim("response_type", ResponseType.CODE.toString())
        .claim("scope", scope.toString())
        .claim("redirect_uri", this.relyingParty.getRedirectUri().toString());
  }

  /**
   * Adds the state, nonce, PKCE and user message, signs the Request Object and creates the request.
   *
   * @param op the OP
   * @param scope the scope
   * @param claims the Request Object claims
   * @param signMessage the sign message (for signature approval)
   * @param expectedIdentity the authentication the signature approval is bound to
   * @return the request
   */
  private @NonNull OidcRequest createRequest(final @NonNull OpenIdProvider op, final @NonNull Scope scope,
      final JWTClaimsSet.@NonNull Builder claims, final @Nullable String signMessage,
      final @Nullable OidcAuthentication expectedIdentity) {

    final State state = new State();
    final Nonce nonce = new Nonce();
    final CodeVerifier codeVerifier = new CodeVerifier();
    final CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

    claims.claim("state", state.getValue())
        .claim("nonce", nonce.getValue())
        .claim("code_challenge", codeChallenge.getValue())
        .claim("code_challenge_method", CodeChallengeMethod.S256.getValue());

    final UserMessage userMessage = this.userMessage(op);
    if (userMessage != null) {
      claims.claim(ParameterConstants.USER_MESSAGE_PARAM_NAME, encode(userMessage));
    }

    final SignedJWT requestObject = this.sign(claims.build());

    final Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("response_type", ResponseType.CODE.toString());
    parameters.put("client_id", this.relyingParty.getClientId().getValue());
    parameters.put("scope", scope.toString());
    parameters.put("request", requestObject.serialize());

    final URI endpoint = op.getMetadata().getAuthorizationEndpointURI();
    if (endpoint == null) {
      throw new IllegalArgumentException("OP '%s' has no authorization endpoint".formatted(op.getIssuer()));
    }
    log.debug("Created {} request for OP '{}' [scope='{}']",
        signMessage != null ? "signature approval" : "authentication", op.getIssuer(), scope);

    return new OidcRequest(endpoint, parameters, requestObject,
        new OidcRequestState(op.getIssuer(), state.getValue(), nonce.getValue(), codeVerifier.getValue(),
            signMessage, expectedIdentity));
  }

  /**
   * Creates the user message for the OP, if it declares support for user messages.
   *
   * @param op the OP
   * @return the user message, or {@code null}
   */
  private @Nullable UserMessage userMessage(final @NonNull OpenIdProvider op) {
    if (!Boolean.TRUE.equals(op.getDocument().get(ParameterConstants.USER_MESSAGE_SUPPORTED_PARAM_NAME))) {
      return null;
    }
    final boolean markdown = op.getStringList(ParameterConstants.USER_MESSAGE_SUPPORTED_MIMETYPES_PARAM_NAME)
        .contains(UserMessage.MARKDOWN_MIME_TYPE);
    final Map<String, String> templates = markdown ? this.markdownUserMessages : this.plainUserMessages;
    if (templates.isEmpty()) {
      return null;
    }
    final List<UserMessage.Message> messages = new ArrayList<>();
    templates.forEach((lang, text) -> messages.add(new UserMessage.Message(text, lang)));
    return new UserMessage(messages, markdown ? UserMessage.MARKDOWN_MIME_TYPE : UserMessage.TEXT_MIME_TYPE);
  }

  /**
   * Gets the JSON representation of a user message (also used for {@code sign_message}) with every {@code message}
   * and {@code message#<lang>} value given as the Base64 encoding of its UTF-8 string, as Section 2.1 of
   * Authentication Request Parameter Extensions for the Swedish OpenID Connect Profile 1.1 requires. The
   * {@code UserMessage} class of oidc-sweden-nimbus puts the plain text in these fields.
   *
   * @param userMessage the user message
   * @return the JSON object to send
   */
  static @NonNull JSONObject encode(final @NonNull UserMessage userMessage) {
    final JSONObject json = userMessage.toJSONObject();
    for (final Map.Entry<String, Object> e : json.entrySet()) {
      if ((UserMessage.MESSAGE_PARAMETER_NAME.equals(e.getKey())
          || e.getKey().startsWith(UserMessage.MESSAGE_PARAMETER_NAME + "#"))
          && e.getValue() instanceof final String message) {
        e.setValue(Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8)));
      }
    }
    return json;
  }

  /**
   * Signs a Request Object with the RP's OIDC signing key.
   *
   * @param claims the claims
   * @return the signed Request Object
   */
  private @NonNull SignedJWT sign(final @NonNull JWTClaimsSet claims) {
    try {
      final JWSHeader header = new JWSHeader.Builder(this.relyingParty.getSignatureAlgorithm())
          .keyID(this.relyingParty.getSignJwk().getKeyID())
          .build();
      final SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(JoseSupport.signer(this.relyingParty.getSignCredential()));
      return jwt;
    }
    catch (final JOSEException e) {
      throw new IllegalStateException("Failed to sign Request Object - " + e.getMessage(), e);
    }
  }

  /**
   * Creates an essential claim request with a value.
   *
   * @param value the value
   * @return the claim request
   */
  private static @NonNull JSONObject essential(final @NonNull String value) {
    final JSONObject o = new JSONObject();
    o.put("essential", true);
    o.put("value", value);
    return o;
  }

  /**
   * A created OIDC request.
   *
   * @param endpoint the authorization endpoint to POST to
   * @param parameters the parameters to POST
   * @param requestObject the signed Request Object
   * @param state the state to keep in the session
   */
  public record OidcRequest(@NonNull URI endpoint, @NonNull Map<String, String> parameters,
      @NonNull SignedJWT requestObject, @NonNull OidcRequestState state) {
  }

}
