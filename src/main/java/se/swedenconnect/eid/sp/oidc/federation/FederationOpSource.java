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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.oidc.OpenIdProvider;
import se.swedenconnect.eid.sp.oidc.federation.FederationClient.FederationException;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Finds the OpenID Providers of the federation: the listing sources are asked for entities of type
 * {@code openid_provider}, and every OP found is resolved through the trust anchor. Listing and resolving run at one
 * interval, and a failed resolve is retried after a shorter interval. An OP whose resolve response has expired
 * without a successful refresh is no longer returned.
 *
 * @author Martin Lindström
 */
public class FederationOpSource {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationOpSource.class);

  /** The entity type for OPs. */
  public static final @NonNull String OPENID_PROVIDER = "openid_provider";

  /** Resolves entities through the trust anchor. */
  private final @NonNull TrustAnchorResolver resolver;

  /** The federation client. */
  private final @NonNull FederationClient client;

  /** The listing sources. */
  private final @NonNull List<RpConfigurationProperties.ListingSource> listingSources;

  /** The refresh interval. */
  private final @NonNull Duration refreshInterval;

  /** The retry interval. */
  private final @NonNull Duration retryInterval;

  /** The clock. */
  private final @NonNull Clock clock;

  /** The OPs found, where the key is the entity identifier. */
  private final @NonNull Map<String, Entry> entries = new LinkedHashMap<>();

  /** When the next listing is due. */
  private @NonNull Instant nextListing = Instant.EPOCH;

  /**
   * Constructor.
   *
   * @param resolver resolves entities through the trust anchor
   * @param client the federation client
   * @param listingSources the listing sources
   * @param refreshInterval the refresh interval
   * @param retryInterval the retry interval
   * @param clock the clock
   */
  public FederationOpSource(final @NonNull TrustAnchorResolver resolver, final @NonNull FederationClient client,
      final @NonNull List<RpConfigurationProperties.ListingSource> listingSources,
      final @NonNull Duration refreshInterval, final @NonNull Duration retryInterval, final @NonNull Clock clock) {
    this.resolver = Objects.requireNonNull(resolver, "resolver must be set");
    this.client = Objects.requireNonNull(client, "client must be set");
    this.listingSources = List.copyOf(listingSources);
    this.refreshInterval = Objects.requireNonNull(refreshInterval, "refreshInterval must be set");
    this.retryInterval = Objects.requireNonNull(retryInterval, "retryInterval must be set");
    this.clock = Objects.requireNonNull(clock, "clock must be set");
  }

  /**
   * Gets the OPs whose resolved metadata has not expired.
   *
   * @return a list of OPs
   */
  public synchronized @NonNull List<OpenIdProvider> getProviders() {
    final Instant now = this.clock.instant();
    final List<OpenIdProvider> providers = new ArrayList<>();
    for (final Entry entry : this.entries.values()) {
      final OpenIdProvider op = entry.provider;
      if (op != null && op.getExpiresAt() != null && op.getExpiresAt().isAfter(now)) {
        providers.add(op);
      }
    }
    return providers;
  }

  /**
   * Lists and resolves OPs when due, and retries failed resolves.
   */
  public synchronized void refreshDue() {
    final Instant now = this.clock.instant();
    if (!now.isBefore(this.nextListing)) {
      this.listAndResolve(now);
      return;
    }
    for (final Map.Entry<String, Entry> e : this.entries.entrySet()) {
      if (!now.isBefore(e.getValue().nextResolve)) {
        this.resolve(e.getKey(), e.getValue(), now);
      }
    }
  }

  /**
   * Asks the listing sources for OPs and resolves every OP found.
   *
   * @param now the current time
   */
  private void listAndResolve(final @NonNull Instant now) {
    final Set<String> found = new LinkedHashSet<>();
    boolean anyListingSucceeded = false;
    for (final RpConfigurationProperties.ListingSource source : this.listingSources) {
      final String sourceId = Objects.requireNonNull(source.getEntityId());
      try {
        final URI endpoint = source.getListEndpoint() != null
            ? URI.create(source.getListEndpoint())
            : this.listEndpoint(sourceId);
        found.addAll(this.client.list(endpoint, OPENID_PROVIDER));
        anyListingSucceeded = true;
      }
      catch (final FederationException | RuntimeException e) {
        log.warn("Failed to list OPs of {} - {}", sourceId, e.getMessage());
      }
    }
    if (!anyListingSucceeded && !this.listingSources.isEmpty()) {
      log.warn("No listing source could be listed - retrying in {}", this.retryInterval);
      this.nextListing = now.plus(this.retryInterval);
      // Keep the OPs we have until their resolve responses expire
      for (final Map.Entry<String, Entry> e : this.entries.entrySet()) {
        if (!now.isBefore(e.getValue().nextResolve)) {
          this.resolve(e.getKey(), e.getValue(), now);
        }
      }
      return;
    }
    this.nextListing = now.plus(this.refreshInterval);
    this.entries.keySet().removeIf(id -> {
      if (!found.contains(id)) {
        log.info("OP {} is no longer listed in the federation", id);
        return true;
      }
      return false;
    });
    for (final String id : found) {
      this.resolve(id, this.entries.computeIfAbsent(id, i -> new Entry()), now);
    }
    log.debug("Federation refresh done - {} OPs listed, {} usable", found.size(), this.getProviders().size());
  }

  /**
   * Resolves an OP. A failed resolve keeps the current metadata (until it expires) and is retried after the retry
   * interval.
   *
   * @param entityId the OP's entity identifier
   * @param entry the entry to update
   * @param now the current time
   */
  private void resolve(final @NonNull String entityId, final @NonNull Entry entry, final @NonNull Instant now) {
    try {
      final TrustAnchorResolver.ResolvedEntity resolved = this.resolver.resolve(entityId, OPENID_PROVIDER);
      final Object md = resolved.metadata().get(OPENID_PROVIDER);
      if (!(md instanceof final Map<?, ?> opMetadata)) {
        throw new FederationException("The resolve response for %s has no openid_provider metadata"
            .formatted(entityId));
      }
      @SuppressWarnings("unchecked")
      final JSONObject document = new JSONObject((Map<String, Object>) opMetadata);
      final OpenIdProvider op = new OpenIdProvider(document, OpenIdProvider.Source.FEDERATION,
          this.trustMarkTypes(entityId, resolved.trustMarks(), now), entityId, resolved.expiresAt());
      if (!entityId.equals(op.getIssuer())) {
        throw new FederationException("The issuer %s of OP %s does not equal its entity identifier"
            .formatted(op.getIssuer(), entityId));
      }
      entry.provider = op;
      entry.nextResolve = now.plus(this.refreshInterval);
      log.debug("Resolved OP {} [trust marks={}, exp={}]", entityId, op.getTrustMarkTypes(), op.getExpiresAt());
    }
    catch (final FederationException | ParseException | RuntimeException e) {
      entry.nextResolve = now.plus(this.retryInterval);
      log.warn("Failed to resolve OP {} - {} (retry in {})", entityId, e.getMessage(), this.retryInterval);
    }
  }

  /**
   * Gets the types of the trust marks in a resolve response that are issued to the OP and have not expired. The
   * resolver has verified them.
   *
   * @param entityId the OP's entity identifier
   * @param trustMarks the trust marks of the resolve response
   * @param now the current time
   * @return the trust mark types
   */
  private @NonNull List<String> trustMarkTypes(final @NonNull String entityId,
      final @NonNull List<Map<String, Object>> trustMarks, final @NonNull Instant now) {
    final List<String> types = new ArrayList<>();
    for (final Map<String, Object> mark : trustMarks) {
      final Object type = mark.get("trust_mark_type");
      final Object value = mark.get("trust_mark");
      if (!(type instanceof final String typeString) || !(value instanceof final String jwt)) {
        continue;
      }
      try {
        final JWTClaimsSet claims = SignedJWT.parse(jwt).getJWTClaimsSet();
        if (!entityId.equals(claims.getSubject())) {
          continue;
        }
        if (claims.getExpirationTime() != null && !claims.getExpirationTime().toInstant().isAfter(now)) {
          continue;
        }
        final Object claimType = claims.getClaim("trust_mark_type");
        if (claimType != null && !typeString.equals(claimType)) {
          continue;
        }
        types.add(typeString);
      }
      catch (final java.text.ParseException e) {
        log.debug("Ignoring invalid trust mark {} for {}", typeString, entityId);
      }
    }
    return types;
  }

  /**
   * Gets the listing endpoint of a listing source from its resolved (or, for the trust anchor, verified) metadata.
   *
   * @param sourceId the listing source
   * @return the listing endpoint
   * @throws FederationException if it can not be determined
   */
  private @NonNull URI listEndpoint(final @NonNull String sourceId) throws FederationException {
    final Map<String, Object> metadata = this.resolver.getTrustAnchorId().equals(sourceId)
        ? this.resolver.getTrustAnchorMetadata()
        : this.resolver.resolve(sourceId, null).metadata();
    final URI endpoint = FederationClient.federationEndpoint(metadata, "federation_list_endpoint");
    if (endpoint == null) {
      throw new FederationException("%s does not publish a federation_list_endpoint".formatted(sourceId));
    }
    return endpoint;
  }

  /**
   * An OP found in the federation.
   */
  private static class Entry {

    /** The OP (null until it has been resolved). */
    private @Nullable OpenIdProvider provider;

    /** When the next resolve is due. */
    private @NonNull Instant nextResolve = Instant.EPOCH;
  }

}
