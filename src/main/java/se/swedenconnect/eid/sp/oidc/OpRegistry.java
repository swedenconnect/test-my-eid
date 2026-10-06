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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Registry for the OpenID Providers that the RP can use. It holds the manually configured OPs, whose discovery
 * documents are fetched and refreshed in the background, and the OPs found through the OpenID Federation (when
 * enabled).
 *
 * @author Martin Lindström
 */
public class OpRegistry {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(OpRegistry.class);

  /** Timeout for fetching discovery documents. */
  private static final int HTTP_TIMEOUT_MILLIS = 10_000;

  /** The manually configured OPs. */
  private final @NonNull List<ManualEntry> manualEntries;

  /** Issuers of OPs that should not be listed. */
  private final @NonNull List<String> blackList;

  /** How often discovery documents are refreshed. */
  private final @NonNull Duration refreshInterval;

  /** How soon a failed fetch is retried. */
  private final @NonNull Duration retryInterval;

  /** The clock. */
  private final @NonNull Clock clock;

  /** Fetches discovery documents. */
  private @NonNull DiscoveryDocumentFetcher fetcher = OpRegistry::fetchDiscoveryDocument;

  /** Supplies the OPs found through the OpenID Federation (empty when federation is disabled). */
  private @NonNull Supplier<List<OpenIdProvider>> federationProviders = List::of;

  /** The background executor. */
  private @Nullable ScheduledExecutorService executor;

  /**
   * Constructor.
   *
   * @param providers the manually configured OPs
   * @param discovery settings for listing and refreshing OPs
   * @param clock the clock
   */
  public OpRegistry(final @NonNull List<RpConfigurationProperties.ProviderConfig> providers,
      final RpConfigurationProperties.@NonNull Discovery discovery, final @NonNull Clock clock) {
    this.blackList = List.copyOf(discovery.getBlackList());
    this.refreshInterval = discovery.getRefreshInterval();
    this.retryInterval = discovery.getRetryInterval();
    this.clock = Objects.requireNonNull(clock, "clock must be set");
    this.manualEntries = new ArrayList<>();
    for (final RpConfigurationProperties.ProviderConfig config : providers) {
      final String issuer = Objects.requireNonNull(config.getIssuer(), "issuer must be set");
      if (this.manualEntries.stream().anyMatch(e -> e.issuer.equals(issuer))) {
        throw new IllegalStateException("OP '%s' is configured more than once under rp.providers".formatted(issuer));
      }
      this.manualEntries.add(new ManualEntry(issuer, config));
    }
  }

  /**
   * Starts the background refresh of discovery documents. The first fetch is made directly, but asynchronously, so a
   * failing OP never stops startup.
   */
  public synchronized void start() {
    if (this.executor != null || this.manualEntries.isEmpty()) {
      return;
    }
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread t = new Thread(r, "op-registry-refresh");
      t.setDaemon(true);
      return t;
    });
    final long period = Math.max(1, Math.min(30, Math.min(this.retryInterval.toSeconds(),
        this.refreshInterval.toSeconds()) / 2));
    this.executor.scheduleWithFixedDelay(this::refreshDue, 0, period, TimeUnit.SECONDS);
  }

  /**
   * Stops the background refresh.
   */
  public synchronized void stop() {
    if (this.executor != null) {
      this.executor.shutdownNow();
      this.executor = null;
    }
  }

  /**
   * Fetches the discovery documents of the manually configured OPs that are due for a refresh (or retry).
   */
  public void refreshDue() {
    final Instant now = this.clock.instant();
    for (final ManualEntry entry : this.manualEntries) {
      if (this.blackList.contains(entry.issuer)) {
        continue;
      }
      if (entry.isDue(now)) {
        try {
          entry.refresh(now);
        }
        catch (final RuntimeException e) {
          log.error("Unexpected error refreshing OP '{}'", entry.issuer, e);
        }
      }
    }
  }

  /**
   * Gets all OPs that can be listed: the manually configured OPs that have a discovery document, and the OPs found
   * through the federation whose issuer is not configured manually. Black-listed OPs are left out.
   *
   * @return a list of OPs
   */
  public @NonNull List<OpenIdProvider> getProviders() {
    final List<OpenIdProvider> providers = new ArrayList<>();
    for (final ManualEntry entry : this.manualEntries) {
      if (this.blackList.contains(entry.issuer)) {
        log.trace("OP '{}' is black-listed", entry.issuer);
        continue;
      }
      final OpenIdProvider op = entry.provider;
      if (op != null) {
        providers.add(op);
      }
    }
    for (final OpenIdProvider op : Optional.ofNullable(this.federationProviders.get()).orElse(List.of())) {
      if (this.blackList.contains(op.getIssuer())) {
        log.trace("OP '{}' is black-listed", op.getIssuer());
        continue;
      }
      if (this.isManuallyConfigured(op.getIssuer())) {
        log.trace("OP '{}' is configured manually - ignoring federation entry", op.getIssuer());
        continue;
      }
      if (providers.stream().noneMatch(p -> p.getIssuer().equals(op.getIssuer()))) {
        providers.add(op);
      }
    }
    return Collections.unmodifiableList(providers);
  }

  /**
   * Gets a listed OP by its issuer.
   *
   * @param issuer the issuer
   * @return the OP, or {@code null} if it is not listed
   */
  public @Nullable OpenIdProvider getProvider(final @NonNull String issuer) {
    return this.getProviders().stream().filter(p -> p.getIssuer().equals(issuer)).findFirst().orElse(null);
  }

  /**
   * Tells whether the issuer is configured manually.
   *
   * @param issuer the issuer
   * @return {@code true} if the issuer is configured under {@code rp.providers}
   */
  public boolean isManuallyConfigured(final @NonNull String issuer) {
    return this.manualEntries.stream().anyMatch(e -> e.issuer.equals(issuer));
  }

  /**
   * Fetches a discovery document from {@code <issuer>/.well-known/openid-configuration}.
   *
   * @param issuer the issuer
   * @return the discovery document
   * @throws IOException for communication errors
   * @throws ParseException for invalid responses
   */
  private static @NonNull JSONObject fetchDiscoveryDocument(final @NonNull String issuer)
      throws IOException, ParseException {
    final HTTPRequest request = new OIDCProviderConfigurationRequest(new Issuer(issuer)).toHTTPRequest();
    request.setConnectTimeout(HTTP_TIMEOUT_MILLIS);
    request.setReadTimeout(HTTP_TIMEOUT_MILLIS);
    final HTTPResponse response = request.send();
    response.ensureStatusCode(HTTPResponse.SC_OK);
    return response.getBodyAsJSONObject();
  }

  /**
   * Fetches discovery documents.
   */
  @FunctionalInterface
  public interface DiscoveryDocumentFetcher {

    /**
     * Fetches the discovery document for the issuer.
     *
     * @param issuer the issuer
     * @return the discovery document
     * @throws IOException for communication errors
     * @throws ParseException for invalid responses
     */
    @NonNull JSONObject fetch(final @NonNull String issuer) throws IOException, ParseException;
  }

  /**
   * State for a manually configured OP.
   */
  private class ManualEntry {

    /** The issuer. */
    private final @NonNull String issuer;

    /** The configuration. */
    private final RpConfigurationProperties.@NonNull ProviderConfig config;

    /** The OP, set when a discovery document has been obtained. */
    private volatile @Nullable OpenIdProvider provider;

    /** When the next fetch is due. */
    private @NonNull Instant nextFetch = Instant.EPOCH;

    /** Whether the document is given in the configuration (and never fetched). */
    private final boolean configured;

    /**
     * Constructor.
     *
     * @param issuer the issuer
     * @param config the configuration
     */
    ManualEntry(final @NonNull String issuer, final RpConfigurationProperties.@NonNull ProviderConfig config) {
      this.issuer = issuer;
      this.config = config;
      this.configured = StringUtils.hasText(config.getDiscoveryDocument())
          || config.getDiscoveryDocumentResource() != null;
      if (this.configured) {
        this.provider = this.loadConfigured();
        this.nextFetch = Instant.MAX;
      }
    }

    /**
     * Tells whether a fetch is due.
     *
     * @param now the current time
     * @return {@code true} if a fetch should be made
     */
    boolean isDue(final @NonNull Instant now) {
      return !this.configured && !now.isBefore(this.nextFetch);
    }

    /**
     * Fetches the discovery document. A failed fetch keeps the last fetched document and is retried after the retry
     * interval.
     *
     * @param now the current time
     */
    void refresh(final @NonNull Instant now) {
      try {
        final JSONObject document = OpRegistry.this.fetcher.fetch(this.issuer);
        this.provider = this.toProvider(document);
        this.nextFetch = now.plus(OpRegistry.this.refreshInterval);
        log.debug("Fetched discovery document for OP '{}'", this.issuer);
      }
      catch (final IOException | ParseException | IllegalArgumentException e) {
        this.nextFetch = now.plus(OpRegistry.this.retryInterval);
        if (this.provider == null) {
          log.warn("No discovery document for OP '{}' - it is not listed (retry in {}): {}",
              this.issuer, OpRegistry.this.retryInterval, e.getMessage());
        }
        else {
          log.warn("Failed to refresh discovery document for OP '{}' - keeping last fetched document (retry in {}): "
              + "{}", this.issuer, OpRegistry.this.retryInterval, e.getMessage());
        }
      }
    }

    /**
     * Loads a discovery document given in the configuration.
     *
     * @return the OP, or {@code null} if the document is invalid
     */
    private @Nullable OpenIdProvider loadConfigured() {
      try {
        final String json;
        if (StringUtils.hasText(this.config.getDiscoveryDocument())) {
          json = this.config.getDiscoveryDocument();
        }
        else {
          try (final InputStream is = Objects.requireNonNull(this.config.getDiscoveryDocumentResource())
              .getInputStream()) {
            json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
          }
        }
        return this.toProvider(JSONObjectUtils.parse(json));
      }
      catch (final IOException | ParseException | IllegalArgumentException e) {
        log.warn("Invalid discovery document configured for OP '{}' - it is not listed: {}",
            this.issuer, e.getMessage());
        return null;
      }
    }

    /**
     * Creates the OP from a discovery document, and makes sure that its {@code issuer} equals the configured issuer.
     *
     * @param document the discovery document
     * @return the OP
     * @throws ParseException for invalid documents
     */
    private @NonNull OpenIdProvider toProvider(final @NonNull JSONObject document) throws ParseException {
      final OpenIdProvider op = new OpenIdProvider(document, OpenIdProvider.Source.MANUAL, List.of());
      if (!this.issuer.equals(op.getIssuer())) {
        throw new IllegalArgumentException("Discovery document issuer '%s' does not equal configured issuer '%s'"
            .formatted(op.getIssuer(), this.issuer));
      }
      return op;
    }
  }

  /**
   * Assigns the fetcher of discovery documents.
   *
   * @param fetcher the fetcher of discovery documents
   */
  public void setFetcher(final @NonNull DiscoveryDocumentFetcher fetcher) {
    this.fetcher = fetcher;
  }

  /**
   * Assigns the supplier of the OPs found through the OpenID Federation.
   *
   * @param federationProviders the supplier of the OPs found through the OpenID Federation
   */
  public void setFederationProviders(final @NonNull Supplier<List<OpenIdProvider>> federationProviders) {
    this.federationProviders = federationProviders;
  }

}
