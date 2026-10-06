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
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.sun.net.httpserver.HttpExchange;
import net.minidev.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * A test double for an OpenID Provider, running on a local HTTP server.
 */
public class TestOidcProvider implements AutoCloseable {

  /** The HTTP server. */
  private final TestOpServer server;

  /** The OP signing key. */
  private final RSAKey signingKey;

  /** Another key, not published, used to produce bad signatures. */
  private final RSAKey otherKey;

  /** Pending codes. */
  private final Map<String, Pending> codes = new ConcurrentHashMap<>();

  /** The access tokens issued. */
  private final Map<String, Pending> accessTokens = new ConcurrentHashMap<>();

  /** Errors found when validating token requests. */
  public final List<String> tokenRequestErrors = new ArrayList<>();

  /** The client ID of the RP. */
  public volatile String clientId;

  /** The RP's public signing key (to validate client assertions). */
  public volatile RSAKey rpSigningKey;

  /** The RP's public encryption key (when encryption is on). */
  public volatile RSAKey rpEncryptionKey;

  /** Modifies the ID token claims. */
  public volatile Consumer<JWTClaimsSet.Builder> idTokenCustomizer = b -> {
  };

  /** Modifies the UserInfo claims. */
  public volatile Consumer<JWTClaimsSet.Builder> userInfoCustomizer = b -> {
  };

  /** Whether the ID token should be signed with an unpublished key. */
  public volatile boolean badIdTokenSignature = false;

  /** Whether UserInfo should be returned as plain JSON. */
  public volatile boolean unsignedUserInfo = false;

  /** The claims about the user. */
  public volatile Map<String, Object> userClaims = Map.of(
      "https://id.oidc.se/claim/personalIdentityNumber", "197705232382",
      "given_name", "Frida",
      "family_name", "Kranstege",
      "name", "Frida Kranstege",
      "birthdate", "1977-05-23");

  /** The acr to issue. */
  public volatile String acr = "http://id.elegnamnden.se/loa/1.0/loa3";

  /** The scopes supported. */
  public volatile List<String> scopesSupported = List.of("openid",
      "https://id.oidc.se/scope/naturalPersonInfo", "https://id.oidc.se/scope/naturalPersonNumber");

  /** Additional discovery document parameters. */
  public final Map<String, Object> extraMetadata = new ConcurrentHashMap<>();

  /**
   * A pending authorization.
   *
   * @param nonce the nonce
   * @param codeChallenge the code challenge
   */
  record Pending(String nonce, String codeChallenge) {
  }

  /**
   * Starts the OP.
   *
   * @throws Exception for errors
   */
  public TestOidcProvider() throws Exception {
    this.server = new TestOpServer();
    this.signingKey = new RSAKeyGenerator(2048).keyID("op-key").generate();
    this.otherKey = new RSAKeyGenerator(2048).keyID("op-key").generate();
    this.server.on("/.well-known/openid-configuration", e -> TestOpServer.Response.json(this.discoveryDocument()));
    this.server.on("/jwks", e -> TestOpServer.Response.json(
        new JSONObject(new JWKSet(this.signingKey).toPublicJWKSet().toJSONObject())));
    this.server.on("/token", this::token);
    this.server.on("/userinfo", this::userInfo);
  }

  /**
   * Gets the issuer.
   *
   * @return the issuer
   */
  public String getIssuer() {
    return this.server.getBaseUrl();
  }

  /**
   * Gets the discovery document.
   *
   * @return the discovery document
   */
  public JSONObject discoveryDocument() {
    final JSONObject doc = TestOpServer.discoveryDocument(this.getIssuer());
    doc.put("scopes_supported", TestOpServer.array(this.scopesSupported));
    doc.put("acr_values_supported", TestOpServer.array(List.of(
        "http://id.elegnamnden.se/loa/1.0/loa3", "http://id.swedenconnect.se/loa/1.0/uncertified-loa3")));
    doc.put("token_endpoint_auth_methods_supported", TestOpServer.array(List.of("private_key_jwt")));
    doc.put("https://id.oidc.se/disco/userMessageSupported", true);
    doc.put("https://id.oidc.se/disco/userMessageSupportedMimeTypes", TestOpServer.array(List.of("text/plain")));
    doc.putAll(this.extraMetadata);
    return doc;
  }

  /**
   * Simulates the authorization endpoint: registers a code for the request.
   *
   * @param requestObject the Request Object sent by the RP
   * @return the code
   * @throws Exception for errors
   */
  public String authorize(final SignedJWT requestObject) throws Exception {
    final JWTClaimsSet claims = requestObject.getJWTClaimsSet();
    final String code = UUID.randomUUID().toString();
    this.codes.put(code, new Pending(claims.getStringClaim("nonce"), claims.getStringClaim("code_challenge")));
    return code;
  }

  private TestOpServer.Response token(final HttpExchange exchange) {
    try {
      final Map<String, List<String>> params = URLUtils.parseParameters(
          new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      final String code = MultivaluedMapUtils.getFirstValue(params, "code");
      final Pending pending = this.codes.remove(code);
      if (pending == null) {
        return error("invalid_grant");
      }
      // Validate client authentication
      final SignedJWT assertion = SignedJWT.parse(MultivaluedMapUtils.getFirstValue(params, "client_assertion"));
      if (!"urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(
          MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
        this.tokenRequestErrors.add("client_assertion_type");
      }
      if (!assertion.verify(new RSASSAVerifier(this.rpSigningKey))) {
        this.tokenRequestErrors.add("client_assertion signature");
      }
      final JWTClaimsSet ac = assertion.getJWTClaimsSet();
      if (!ac.getAudience().equals(List.of(this.getIssuer() + "/token"))) {
        this.tokenRequestErrors.add("client_assertion aud " + ac.getAudience());
      }
      if (!this.clientId.equals(ac.getIssuer()) || !this.clientId.equals(ac.getSubject())) {
        this.tokenRequestErrors.add("client_assertion iss/sub");
      }
      // PKCE
      final String verifier = MultivaluedMapUtils.getFirstValue(params, "code_verifier");
      if (verifier == null || !CodeChallenge.compute(CodeChallengeMethod.S256, new CodeVerifier(verifier))
          .getValue().equals(pending.codeChallenge())) {
        this.tokenRequestErrors.add("code_verifier");
        return error("invalid_grant");
      }

      final Instant now = Instant.now();
      final JWTClaimsSet.Builder idToken = new JWTClaimsSet.Builder()
          .issuer(this.getIssuer())
          .subject("user-1")
          .audience(this.clientId)
          .issueTime(Date.from(now))
          .expirationTime(Date.from(now.plusSeconds(300)))
          .claim("auth_time", now.getEpochSecond())
          .claim("nonce", pending.nonce())
          .claim("acr", this.acr);
      this.userClaims.forEach(idToken::claim);
      this.idTokenCustomizer.accept(idToken);

      final String accessToken = UUID.randomUUID().toString();
      this.accessTokens.put(accessToken, pending);

      final JSONObject response = new JSONObject();
      response.put("access_token", accessToken);
      response.put("token_type", "Bearer");
      response.put("expires_in", 300);
      response.put("id_token", this.jwt(idToken.build(), this.badIdTokenSignature ? this.otherKey : this.signingKey));
      return TestOpServer.Response.json(response);
    }
    catch (final Exception e) {
      this.tokenRequestErrors.add(e.toString());
      return error("server_error");
    }
  }

  private TestOpServer.Response userInfo(final HttpExchange exchange) {
    final String auth = exchange.getRequestHeaders().getFirst("Authorization");
    if (auth == null || !auth.startsWith("Bearer ") || !this.accessTokens.containsKey(auth.substring(7))
        || !"GET".equals(exchange.getRequestMethod())) {
      return new TestOpServer.Response(401, "application/json", "{\"error\":\"invalid_token\"}");
    }
    final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(this.getIssuer())
        .subject("user-1")
        .audience(this.clientId);
    this.userClaims.forEach(claims::claim);
    this.userInfoCustomizer.accept(claims);
    if (this.unsignedUserInfo) {
      return TestOpServer.Response.json(new JSONObject(claims.build().toJSONObject()));
    }
    try {
      return new TestOpServer.Response(200, "application/jwt", this.jwt(claims.build(), this.signingKey));
    }
    catch (final Exception e) {
      return error("server_error");
    }
  }

  private String jwt(final JWTClaimsSet claims, final RSAKey key) throws Exception {
    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
        claims);
    jwt.sign(new RSASSASigner(key));
    if (this.rpEncryptionKey == null) {
      return jwt.serialize();
    }
    final JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .contentType("JWT").build(), new Payload(jwt));
    jwe.encrypt(new RSAEncrypter(this.rpEncryptionKey));
    return jwe.serialize();
  }

  private static TestOpServer.Response error(final String error) {
    return new TestOpServer.Response(400, "application/json", "{\"error\":\"" + error + "\"}");
  }

  /**
   * Gets the URI of an endpoint.
   *
   * @param path the path
   * @return the URI
   */
  public URI uri(final String path) {
    return URI.create(this.getIssuer() + path);
  }

  @Override
  public void close() throws IOException {
    this.server.close();
  }

}
