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
package se.swedenconnect.eid.sp.oidc.federation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.sun.net.httpserver.HttpExchange;
import net.minidev.json.JSONObject;
import se.swedenconnect.eid.sp.oidc.TestOpServer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

/**
 * Test doubles for the federation endpoints: a trust anchor (entity configuration, subordinate listing and resolve)
 * and a trust mark issuer.
 */
public class TestFederation implements AutoCloseable {

  /** The HTTP server. */
  private final TestOpServer server;

  /** The trust anchor key. */
  public final ECKey trustAnchorKey;

  /** The trust mark issuer key. */
  public final ECKey trustMarkIssuerKey;

  /** Another key (not trusted). */
  public final ECKey rogueKey;

  /** The entities that the trust anchor can resolve: entity id to resolved metadata. */
  public final Map<String, Supplier<JSONObject>> resolvable = new ConcurrentHashMap<>();

  /** Trust marks to include in resolve responses: entity id to trust mark types. */
  public final Map<String, List<String>> resolvedTrustMarks = new ConcurrentHashMap<>();

  /** The OPs that the listing endpoint returns. */
  public final List<String> listedOps = new CopyOnWriteArrayList<>();

  /** Lifetime of resolve responses. */
  public volatile Duration resolveLifetime = Duration.ofHours(24);

  /** Lifetime of trust marks. */
  public volatile Duration trustMarkLifetime = Duration.ofDays(30);

  /** Whether the trust mark endpoint fails. */
  public volatile boolean trustMarkIssuerDown = false;

  /** Whether the listing endpoint fails. */
  public volatile boolean listingDown = false;

  /** Whether resolve responses are signed with the rogue key. */
  public volatile boolean rogueResolveSignature = false;

  /** The clock used for issued statements. */
  public volatile Supplier<Instant> now = Instant::now;

  /** The number of calls to the federation endpoints. */
  public final List<String> calls = new CopyOnWriteArrayList<>();

  /**
   * Starts the test federation.
   *
   * @throws Exception for errors
   */
  public TestFederation() throws Exception {
    this.server = new TestOpServer();
    this.trustAnchorKey = new ECKeyGenerator(Curve.P_256).keyID("ta-key").generate();
    this.trustMarkIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("tmi-key").generate();
    this.rogueKey = new ECKeyGenerator(Curve.P_256).keyID("ta-key").generate();

    this.server.on("/ta/.well-known/openid-federation", e -> {
      this.calls.add("ta-ec");
      return this.jwtResponse(this.trustAnchorConfiguration(), "application/entity-statement+jwt");
    });
    this.server.on("/ta/list", e -> {
      this.calls.add("list");
      if (this.listingDown) {
        return new TestOpServer.Response(500, "application/json", "{\"error\":\"server_error\"}");
      }
      return new TestOpServer.Response(200, "application/json", TestOpServer.array(this.listedOps).toJSONString());
    });
    this.server.on("/ta/resolve", this::resolve);
    this.server.on("/tmi/trust-mark", this::trustMark);

    // The trust mark issuer is resolvable
    this.resolvable.put(this.getTrustMarkIssuerId(), () -> {
      final JSONObject fe = new JSONObject();
      fe.put("federation_trust_mark_endpoint", this.getBaseUrl() + "/tmi/trust-mark");
      final JSONObject md = new JSONObject();
      md.put("federation_entity", fe);
      return md;
    });
  }

  /**
   * Gets the base URL.
   *
   * @return the base URL
   */
  public String getBaseUrl() {
    return this.server.getBaseUrl();
  }

  /**
   * Gets the trust anchor's entity identifier.
   *
   * @return the entity identifier
   */
  public String getTrustAnchorId() {
    return this.getBaseUrl() + "/ta";
  }

  /**
   * Gets the trust mark issuer's entity identifier.
   *
   * @return the entity identifier
   */
  public String getTrustMarkIssuerId() {
    return this.getBaseUrl() + "/tmi";
  }

  /**
   * Gets the trust anchor's public key as a JWK set (JSON).
   *
   * @return the JWK set
   */
  public String getTrustAnchorJwks() {
    return new JWKSet(this.trustAnchorKey.toPublicJWK()).toString();
  }

  private JWTClaimsSet trustAnchorConfiguration() {
    final Instant now = this.now.get();
    final JSONObject fe = new JSONObject();
    fe.put("federation_resolve_endpoint", this.getBaseUrl() + "/ta/resolve");
    fe.put("federation_list_endpoint", this.getBaseUrl() + "/ta/list");
    final JSONObject md = new JSONObject();
    md.put("federation_entity", fe);
    return new JWTClaimsSet.Builder()
        .issuer(this.getTrustAnchorId())
        .subject(this.getTrustAnchorId())
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plus(Duration.ofDays(1))))
        .claim("jwks", new JWKSet(this.trustAnchorKey.toPublicJWK()).toJSONObject())
        .claim("metadata", md)
        .build();
  }

  private TestOpServer.Response resolve(final HttpExchange exchange) {
    this.calls.add("resolve");
    final Map<String, List<String>> params = URLUtils.parseParameters(exchange.getRequestURI().getRawQuery());
    final String sub = MultivaluedMapUtils.getFirstValue(params, "sub");
    final String ta = MultivaluedMapUtils.getFirstValue(params, "trust_anchor");
    final Supplier<JSONObject> md = this.resolvable.get(sub);
    if (md == null || !this.getTrustAnchorId().equals(ta)) {
      return new TestOpServer.Response(404, "application/json", "{\"error\":\"not_found\"}");
    }
    try {
      final Instant now = this.now.get();
      final List<Object> marks = new ArrayList<>();
      for (final String type : this.resolvedTrustMarks.getOrDefault(sub, List.of())) {
        final JSONObject m = new JSONObject();
        m.put("trust_mark_type", type);
        m.put("trust_mark", this.trustMarkJwt(type, sub, this.trustMarkIssuerKey).serialize());
        marks.add(m);
      }
      // Trust chain: the subject's (minimal) entity configuration and the trust anchor's subordinate statement
      final ECKey subjectKey = sub.equals(this.getTrustMarkIssuerId()) ? this.trustMarkIssuerKey : this.rogueKey;
      final String leaf = this.sign(new JWTClaimsSet.Builder().issuer(sub).subject(sub)
          .issueTime(Date.from(now)).expirationTime(Date.from(now.plus(Duration.ofDays(1))))
          .claim("jwks", new JWKSet(subjectKey.toPublicJWK()).toJSONObject()).build(),
          subjectKey, "entity-statement+jwt").serialize();
      final String subordinate = this.sign(new JWTClaimsSet.Builder().issuer(this.getTrustAnchorId()).subject(sub)
          .issueTime(Date.from(now)).expirationTime(Date.from(now.plus(Duration.ofDays(1))))
          .claim("jwks", new JWKSet(subjectKey.toPublicJWK()).toJSONObject()).build(),
          this.trustAnchorKey, "entity-statement+jwt").serialize();

      final JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(this.getTrustAnchorId())
          .subject(sub)
          .issueTime(Date.from(now))
          .expirationTime(Date.from(now.plus(this.resolveLifetime)))
          .claim("metadata", md.get())
          .claim("trust_marks", marks)
          .claim("trust_chain", List.of(leaf, subordinate))
          .build();
      return new TestOpServer.Response(200, "application/resolve-response+jwt",
          this.sign(claims, this.rogueResolveSignature ? this.rogueKey : this.trustAnchorKey,
              "resolve-response+jwt").serialize());
    }
    catch (final Exception e) {
      return new TestOpServer.Response(500, "text/plain", e.toString());
    }
  }

  private TestOpServer.Response trustMark(final HttpExchange exchange) {
    this.calls.add("trust-mark");
    if (this.trustMarkIssuerDown) {
      return new TestOpServer.Response(503, "text/plain", "down");
    }
    final Map<String, List<String>> params = URLUtils.parseParameters(exchange.getRequestURI().getRawQuery());
    try {
      return new TestOpServer.Response(200, "application/trust-mark+jwt", this.trustMarkJwt(
          MultivaluedMapUtils.getFirstValue(params, "trust_mark_type"),
          MultivaluedMapUtils.getFirstValue(params, "sub"), this.trustMarkIssuerKey).serialize());
    }
    catch (final Exception e) {
      return new TestOpServer.Response(500, "text/plain", e.toString());
    }
  }

  /**
   * Creates a trust mark.
   *
   * @param type the trust mark type
   * @param sub the subject
   * @param key the signing key
   * @return the trust mark
   * @throws Exception for errors
   */
  public SignedJWT trustMarkJwt(final String type, final String sub, final ECKey key) throws Exception {
    final Instant now = this.now.get();
    return this.sign(new JWTClaimsSet.Builder()
        .issuer(this.getTrustMarkIssuerId())
        .subject(sub)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plus(this.trustMarkLifetime)))
        .claim("trust_mark_type", type)
        .build(), key, "trust-mark+jwt");
  }

  private SignedJWT sign(final JWTClaimsSet claims, final ECKey key, final String type) throws Exception {
    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
        .keyID(key.getKeyID()).type(new JOSEObjectType(type)).build(), claims);
    jwt.sign(new ECDSASigner(key));
    return jwt;
  }

  private TestOpServer.Response jwtResponse(final JWTClaimsSet claims, final String contentType) {
    try {
      return new TestOpServer.Response(200, contentType,
          this.sign(claims, this.trustAnchorKey, "entity-statement+jwt").serialize());
    }
    catch (final Exception e) {
      return new TestOpServer.Response(500, "text/plain", e.toString());
    }
  }

  @Override
  public void close() {
    this.server.close();
  }

}
