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
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.eid.sp.oidc.federation.FederationClient.FederationException;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Resolves entities through the trust anchor's resolve endpoint. Every response is verified with the configured
 * trust anchor key; the trust anchor's self-declared keys are never trusted on their own.
 *
 * @author Martin Lindström
 */
public class TrustAnchorResolver {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(TrustAnchorResolver.class);

  /** The JOSE type of a resolve response. */
  public static final @NonNull JOSEObjectType RESOLVE_RESPONSE_TYPE = new JOSEObjectType("resolve-response+jwt");

  /** The entity identifier of the trust anchor. */
  private final @NonNull String trustAnchorId;

  /** The configured federation keys of the trust anchor. */
  private final @NonNull JWKSet trustAnchorKeys;

  /** The configured resolve endpoint (may be null). */
  private final @Nullable URI configuredResolveEndpoint;

  /** The federation client. */
  private final @NonNull FederationClient client;

  /** The clock. */
  private final @NonNull Clock clock;

  /** The verified entity configuration of the trust anchor (lazily fetched). */
  private volatile @Nullable JWTClaimsSet trustAnchorConfiguration;

  /**
   * Constructor.
   *
   * @param trustAnchorId the entity identifier of the trust anchor
   * @param trustAnchorKeys the configured federation keys of the trust anchor
   * @param configuredResolveEndpoint the configured resolve endpoint ({@code null} to read it from the trust
   *     anchor's entity configuration)
   * @param client the federation client
   * @param clock the clock
   */
  public TrustAnchorResolver(final @NonNull String trustAnchorId, final @NonNull JWKSet trustAnchorKeys,
      final @Nullable URI configuredResolveEndpoint, final @NonNull FederationClient client,
      final @NonNull Clock clock) {
    this.trustAnchorId = Objects.requireNonNull(trustAnchorId, "trustAnchorId must be set");
    this.trustAnchorKeys = Objects.requireNonNull(trustAnchorKeys, "trustAnchorKeys must be set");
    this.configuredResolveEndpoint = configuredResolveEndpoint;
    this.client = Objects.requireNonNull(client, "client must be set");
    this.clock = Objects.requireNonNull(clock, "clock must be set");
  }

  /**
   * Resolves an entity through the trust anchor's resolve endpoint and verifies the response.
   *
   * @param subject the entity to resolve
   * @param entityType the entity type ({@code null} for all types)
   * @return the resolved entity
   * @throws FederationException for errors, or if the response can not be verified
   */
  public @NonNull ResolvedEntity resolve(final @NonNull String subject, final @Nullable String entityType)
      throws FederationException {
    final SignedJWT jwt = this.client.resolve(this.getResolveEndpoint(), subject, this.trustAnchorId, entityType);
    if (!RESOLVE_RESPONSE_TYPE.equals(jwt.getHeader().getType())) {
      throw new FederationException("The resolve response for %s has typ %s - expected %s"
          .formatted(subject, jwt.getHeader().getType(), RESOLVE_RESPONSE_TYPE));
    }
    if (jwt.getHeader().getKeyID() == null) {
      throw new FederationException("The resolve response for %s has no kid".formatted(subject));
    }
    if (!JwtVerifier.verify(jwt, this.trustAnchorKeys)) {
      throw new FederationException(
          "The signature of the resolve response for %s could not be verified with the trust anchor key"
              .formatted(subject));
    }
    final JWTClaimsSet claims = claims(jwt);
    if (!this.trustAnchorId.equals(claims.getIssuer())) {
      throw new FederationException("The resolve response for %s was issued by %s - expected %s"
          .formatted(subject, claims.getIssuer(), this.trustAnchorId));
    }
    if (!subject.equals(claims.getSubject())) {
      throw new FederationException("The resolve response is about %s - expected %s"
          .formatted(claims.getSubject(), subject));
    }
    if (claims.getExpirationTime() == null) {
      throw new FederationException("The resolve response for %s has no exp".formatted(subject));
    }
    final Instant expiresAt = claims.getExpirationTime().toInstant();
    if (!expiresAt.isAfter(this.clock.instant())) {
      throw new FederationException("The resolve response for %s expired at %s".formatted(subject, expiresAt));
    }
    try {
      final Map<String, Object> metadata = claims.getJSONObjectClaim("metadata");
      if (metadata == null) {
        throw new FederationException("The resolve response for %s has no metadata".formatted(subject));
      }
      final List<String> trustChain = claims.getStringListClaim("trust_chain");
      final List<Map<String, Object>> trustMarks = new ArrayList<>();
      final List<Object> marks = claims.getListClaim("trust_marks");
      if (marks != null) {
        for (final Object m : marks) {
          if (m instanceof final Map<?, ?> map) {
            @SuppressWarnings("unchecked")
            final Map<String, Object> mark = (Map<String, Object>) map;
            trustMarks.add(mark);
          }
        }
      }
      return new ResolvedEntity(subject, metadata, trustMarks, trustChain != null ? trustChain : List.of(),
          expiresAt);
    }
    catch (final ParseException e) {
      throw new FederationException("Invalid resolve response for %s - %s".formatted(subject, e.getMessage()), e);
    }
  }

  /**
   * Gets the federation keys of a resolved entity: the keys that its superior's subordinate statement (in the trust
   * chain) holds for it, or the keys of its entity configuration in the verified trust chain. For the trust anchor
   * itself, the configured keys are returned.
   *
   * @param entity the resolved entity
   * @return the entity's federation keys
   * @throws FederationException if no keys are found
   */
  public @NonNull JWKSet getFederationKeys(final @NonNull ResolvedEntity entity) throws FederationException {
    if (this.trustAnchorId.equals(entity.entityId())) {
      return this.trustAnchorKeys;
    }
    final List<String> chain = entity.trustChain();
    try {
      for (int i = chain.size() > 1 ? 1 : 0; i >= 0; i--) {
        final JWTClaimsSet statement = SignedJWT.parse(chain.get(i)).getJWTClaimsSet();
        if (entity.entityId().equals(statement.getSubject()) && statement.getJSONObjectClaim("jwks") != null) {
          return JWKSet.parse(statement.getJSONObjectClaim("jwks"));
        }
      }
    }
    catch (final ParseException | IndexOutOfBoundsException e) {
      throw new FederationException("Invalid trust chain for %s - %s".formatted(entity.entityId(), e.getMessage()),
          e);
    }
    throw new FederationException("No federation keys found for %s in its trust chain".formatted(entity.entityId()));
  }

  /**
   * Gets the {@code metadata} of the trust anchor's own (verified) entity configuration.
   *
   * @return the metadata
   * @throws FederationException for errors
   */
  public @NonNull Map<String, Object> getTrustAnchorMetadata() throws FederationException {
    try {
      final Map<String, Object> metadata = this.getTrustAnchorConfiguration().getJSONObjectClaim("metadata");
      return metadata != null ? metadata : Map.of();
    }
    catch (final ParseException e) {
      throw new FederationException("Invalid trust anchor entity configuration - " + e.getMessage(), e);
    }
  }

  /**
   * Gets the resolve endpoint: the configured one, or the one in the trust anchor's verified entity configuration.
   *
   * @return the resolve endpoint
   * @throws FederationException if it can not be determined
   */
  private @NonNull URI getResolveEndpoint() throws FederationException {
    if (this.configuredResolveEndpoint != null) {
      return this.configuredResolveEndpoint;
    }
    final URI endpoint = FederationClient.federationEndpoint(this.getTrustAnchorMetadata(),
        "federation_resolve_endpoint");
    if (endpoint == null) {
      throw new FederationException("The trust anchor %s does not publish a federation_resolve_endpoint"
          .formatted(this.trustAnchorId));
    }
    return endpoint;
  }

  /**
   * Gets the trust anchor's entity configuration, verified with the configured key.
   *
   * @return the claims of the entity configuration
   * @throws FederationException for errors
   */
  private @NonNull JWTClaimsSet getTrustAnchorConfiguration() throws FederationException {
    final JWTClaimsSet cached = this.trustAnchorConfiguration;
    if (cached != null && cached.getExpirationTime() != null
        && cached.getExpirationTime().toInstant().isAfter(this.clock.instant())) {
      return cached;
    }
    final SignedJWT jwt = this.client.fetchEntityConfiguration(this.trustAnchorId);
    if (!JwtVerifier.verify(jwt, this.trustAnchorKeys)) {
      throw new FederationException("The signature of the trust anchor's entity configuration could not be "
          + "verified with the configured trust anchor key");
    }
    final JWTClaimsSet claims = claims(jwt);
    if (!this.trustAnchorId.equals(claims.getIssuer()) || !this.trustAnchorId.equals(claims.getSubject())) {
      throw new FederationException("The entity configuration of %s has iss %s and sub %s"
          .formatted(this.trustAnchorId, claims.getIssuer(), claims.getSubject()));
    }
    this.trustAnchorConfiguration = claims;
    return claims;
  }

  /**
   * Gets the claims of a JWT.
   *
   * @param jwt the JWT
   * @return the claims
   * @throws FederationException for parse errors
   */
  private static @NonNull JWTClaimsSet claims(final @NonNull SignedJWT jwt) throws FederationException {
    try {
      return jwt.getJWTClaimsSet();
    }
    catch (final ParseException e) {
      throw new FederationException("Invalid JWT claims - " + e.getMessage(), e);
    }
  }

  /**
   * A resolved entity.
   *
   * @param entityId the entity identifier
   * @param metadata the resolved metadata
   * @param trustMarks the verified trust marks ({@code trust_mark_type} and {@code trust_mark})
   * @param trustChain the trust chain from the entity to the trust anchor
   * @param expiresAt when the resolve response expires
   */
  public record ResolvedEntity(@NonNull String entityId, @NonNull Map<String, Object> metadata,
      @NonNull List<Map<String, Object>> trustMarks, @NonNull List<String> trustChain, @NonNull Instant expiresAt) {
  }

  /**
   * Gets the entity identifier of the trust anchor.
   *
   * @return the entity identifier of the trust anchor
   */
  public @NonNull String getTrustAnchorId() {
    return this.trustAnchorId;
  }

}
