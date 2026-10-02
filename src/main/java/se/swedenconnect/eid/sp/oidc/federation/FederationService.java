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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Runs the OpenID Federation tasks in the background: listing and resolving OPs, and keeping the RP's trust marks up
 * to date. Only created when federation is enabled.
 *
 * @author Martin Lindström
 */
public class FederationService {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationService.class);

  /** The OPs found through the federation. */
  private final @NonNull FederationOpSource opSource;

  /** The RP's trust marks. */
  private final @NonNull RpTrustMarkService trustMarkService;

  /** How often due tasks are checked. */
  private final @NonNull Duration checkInterval;

  /** The background executor. */
  private @Nullable ScheduledExecutorService executor;

  /**
   * Constructor.
   *
   * @param opSource the OPs found through the federation
   * @param trustMarkService the RP's trust marks
   * @param retryInterval the retry interval (used to decide how often due tasks are checked)
   */
  public FederationService(final @NonNull FederationOpSource opSource,
      final @NonNull RpTrustMarkService trustMarkService, final @NonNull Duration retryInterval) {
    this.opSource = Objects.requireNonNull(opSource, "opSource must be set");
    this.trustMarkService = Objects.requireNonNull(trustMarkService, "trustMarkService must be set");
    final long seconds = Math.max(1, Math.min(30, retryInterval.toSeconds() / 2));
    this.checkInterval = Duration.ofSeconds(seconds);
  }

  /**
   * Starts the background tasks. The first run is made directly, but asynchronously, so a failing federation never
   * stops startup.
   */
  public synchronized void start() {
    if (this.executor != null) {
      return;
    }
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread t = new Thread(r, "federation-refresh");
      t.setDaemon(true);
      return t;
    });
    this.executor.scheduleWithFixedDelay(this::refreshDue, 0, this.checkInterval.toSeconds(), TimeUnit.SECONDS);
    log.info("OpenID Federation support started");
  }

  /**
   * Stops the background tasks.
   */
  public synchronized void stop() {
    if (this.executor != null) {
      this.executor.shutdownNow();
      this.executor = null;
    }
  }

  /**
   * Runs the tasks that are due.
   */
  public void refreshDue() {
    try {
      this.trustMarkService.refreshDue();
    }
    catch (final RuntimeException e) {
      log.error("Unexpected error refreshing trust marks", e);
    }
    try {
      this.opSource.refreshDue();
    }
    catch (final RuntimeException e) {
      log.error("Unexpected error refreshing federation OPs", e);
    }
  }

  /**
   * Gets the OPs found through the federation.
   *
   * @return the OPs found through the federation
   */
  public @NonNull FederationOpSource getOpSource() {
    return this.opSource;
  }

  /**
   * Gets the RP's trust marks.
   *
   * @return the RP's trust marks
   */
  public @NonNull RpTrustMarkService getTrustMarkService() {
    return this.trustMarkService;
  }

}
