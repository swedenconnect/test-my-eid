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
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.oidc.federation.FederationClient.FederationException;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Requests the RP's own trust marks from the configured trust mark issuers, verifies them and keeps them up to date.
 * A mark is renewed before it expires. A failed fetch keeps the current mark until it expires and is retried; it
 * never stops the service.
 *
 * @author Martin Lindström
 */
public class RpTrustMarkService {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(RpTrustMarkService.class);

  /** The JOSE type of a trust mark. */
  public static final @NonNull JOSEObjectType TRUST_MARK_TYPE = new JOSEObjectType("trust-mark+jwt");

  /** The RP's entity identifier. */
  private final @NonNull String rpEntityId;

  /** Resolves entities through the trust anchor. */
  private final @NonNull TrustAnchorResolver resolver;

  /** The federation client. */
  private final @NonNull FederationClient client;

  /** The refresh interval. */
  private final @NonNull Duration refreshInterval;

  /** The retry interval. */
  private final @NonNull Duration retryInterval;

  /** The clock. */
  private final @NonNull Clock clock;

  /** One entry per issuer and trust mark type. */
  private final @NonNull List<Entry> entries = new ArrayList<>();

  /**
   * Constructor.
   *
   * @param rpEntityId the RP's entity identifier
   * @param issuers the trust mark issuers
   * @param resolver resolves entities through the trust anchor
   * @param client the federation client
   * @param refreshInterval the refresh interval
   * @param retryInterval the retry interval
   * @param clock the clock
   */
  public RpTrustMarkService(final @NonNull String rpEntityId,
      final @NonNull List<RpConfigurationProperties.TrustMarkIssuer> issuers,
      final @NonNull TrustAnchorResolver resolver, final @NonNull FederationClient client,
      final @NonNull Duration refreshInterval, final @NonNull Duration retryInterval, final @NonNull Clock clock) {
    this.rpEntityId = Objects.requireNonNull(rpEntityId, "rpEntityId must be set");
    this.resolver = Objects.requireNonNull(resolver, "resolver must be set");
    this.client = Objects.requireNonNull(client, "client must be set");
    this.refreshInterval = Objects.requireNonNull(refreshInterval, "refreshInterval must be set");
    this.retryInterval = Objects.requireNonNull(retryInterval, "retryInterval must be set");
    this.clock = Objects.requireNonNull(clock, "clock must be set");
    for (final RpConfigurationProperties.TrustMarkIssuer issuer : issuers) {
      for (final String type : issuer.getTrustMarkTypes()) {
        this.entries.add(new Entry(Objects.requireNonNull(issuer.getEntityId()),
            issuer.getTrustMarkEndpoint() != null ? URI.create(issuer.getTrustMarkEndpoint()) : null, type));
      }
    }
  }

  /**
   * Gets the trust marks to publish in the entity configuration: the fetched marks that have not expired.
   *
   * @return a list of trust mark objects ({@code trust_mark_type} and {@code trust_mark})
   */
  public synchronized @NonNull List<JSONObject> getTrustMarks() {
    final Instant now = this.clock.instant();
    final List<JSONObject> marks = new ArrayList<>();
    for (final Entry entry : this.entries) {
      if (entry.trustMark != null && (entry.expiresAt == null || entry.expiresAt.isAfter(now))) {
        final JSONObject mark = new JSONObject();
        mark.put("trust_mark_type", entry.type);
        mark.put("trust_mark", entry.trustMark.serialize());
        marks.add(mark);
      }
    }
    return marks;
  }

  /**
   * Fetches the trust marks that are due for renewal (or retry).
   */
  public synchronized void refreshDue() {
    final Instant now = this.clock.instant();
    for (final Entry entry : this.entries) {
      if (!now.isBefore(entry.nextFetch)) {
        this.fetch(entry, now);
      }
    }
  }

  /**
   * Fetches and verifies a trust mark.
   *
   * @param entry the entry
   * @param now the current time
   */
  private void fetch(final @NonNull Entry entry, final @NonNull Instant now) {
    try {
      final TrustAnchorResolver.ResolvedEntity issuer = this.resolver.resolve(entry.issuer, null);
      final URI endpoint = entry.endpoint != null
          ? entry.endpoint
          : FederationClient.federationEndpoint(issuer.metadata(), "federation_trust_mark_endpoint");
      if (endpoint == null) {
        throw new FederationException("%s does not publish a federation_trust_mark_endpoint"
            .formatted(entry.issuer));
      }
      final SignedJWT mark = this.client.fetchTrustMark(endpoint, entry.type, this.rpEntityId);
      final Instant expiresAt = this.verify(mark, entry, this.resolver.getFederationKeys(issuer), now);

      entry.trustMark = mark;
      entry.expiresAt = expiresAt;
      Instant next = now.plus(this.refreshInterval);
      if (expiresAt != null) {
        // Renew when half of the remaining lifetime has passed
        final Instant halfway = now.plus(Duration.between(now, expiresAt).dividedBy(2));
        if (halfway.isBefore(next)) {
          next = halfway;
        }
      }
      entry.nextFetch = next;
      log.debug("Got trust mark {} from {} [exp={}]", entry.type, entry.issuer, expiresAt);
    }
    catch (final FederationException | RuntimeException e) {
      entry.nextFetch = now.plus(this.retryInterval);
      if (entry.trustMark != null && (entry.expiresAt == null || entry.expiresAt.isAfter(now))) {
        log.warn("Failed to renew trust mark {} from {} - keeping the current one until {} (retry in {}): {}",
            entry.type, entry.issuer, entry.expiresAt, this.retryInterval, e.getMessage());
      }
      else {
        log.warn("Failed to get trust mark {} from {} (retry in {}): {}",
            entry.type, entry.issuer, this.retryInterval, e.getMessage());
      }
    }
  }

  /**
   * Verifies a trust mark: its type, signature (with the issuer's keys obtained through the trust anchor), issuer,
   * subject and trust mark type.
   *
   * @param mark the trust mark
   * @param entry the entry
   * @param issuerKeys the issuer's federation keys
   * @param now the current time
   * @return the expiration time ({@code null} if the mark does not expire)
   * @throws FederationException if the mark is not valid
   */
  private @Nullable Instant verify(final @NonNull SignedJWT mark, final @NonNull Entry entry,
      final @NonNull JWKSet issuerKeys, final @NonNull Instant now) throws FederationException {
    if (!TRUST_MARK_TYPE.equals(mark.getHeader().getType())) {
      throw new FederationException("The trust mark %s has typ %s - expected %s"
          .formatted(entry.type, mark.getHeader().getType(), TRUST_MARK_TYPE));
    }
    if (!JwtVerifier.verify(mark, issuerKeys)) {
      throw new FederationException("The signature of trust mark %s could not be verified with the keys of %s"
          .formatted(entry.type, entry.issuer));
    }
    final JWTClaimsSet claims;
    try {
      claims = mark.getJWTClaimsSet();
    }
    catch (final java.text.ParseException e) {
      throw new FederationException("Invalid trust mark %s - %s".formatted(entry.type, e.getMessage()), e);
    }
    if (!entry.issuer.equals(claims.getIssuer())) {
      throw new FederationException("The trust mark %s was issued by %s - expected %s"
          .formatted(entry.type, claims.getIssuer(), entry.issuer));
    }
    if (!this.rpEntityId.equals(claims.getSubject())) {
      throw new FederationException("The trust mark %s is issued to %s - expected %s"
          .formatted(entry.type, claims.getSubject(), this.rpEntityId));
    }
    if (!entry.type.equals(claims.getClaim("trust_mark_type"))) {
      throw new FederationException("The trust mark has type %s - expected %s"
          .formatted(claims.getClaim("trust_mark_type"), entry.type));
    }
    final Instant expiresAt = claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null;
    if (expiresAt != null && !expiresAt.isAfter(now)) {
      throw new FederationException("The trust mark %s has expired".formatted(entry.type));
    }
    return expiresAt;
  }

  /**
   * A trust mark of a given type from a given issuer.
   */
  private static class Entry {

    /** The issuer. */
    private final @NonNull String issuer;

    /** The configured trust mark endpoint (may be null). */
    private final @Nullable URI endpoint;

    /** The trust mark type. */
    private final @NonNull String type;

    /** The current trust mark. */
    private @Nullable SignedJWT trustMark;

    /** When the current trust mark expires. */
    private @Nullable Instant expiresAt;

    /** When the next fetch is due. */
    private @NonNull Instant nextFetch = Instant.EPOCH;

    /**
     * Constructor.
     *
     * @param issuer the issuer
     * @param endpoint the configured trust mark endpoint
     * @param type the trust mark type
     */
    Entry(final @NonNull String issuer, final @Nullable URI endpoint, final @NonNull String type) {
      this.issuer = issuer;
      this.endpoint = endpoint;
      this.type = type;
    }
  }

}
