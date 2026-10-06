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

import net.minidev.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OpRegistry}.
 */
class OpRegistryTest {

  private static final String WELL_KNOWN = "/.well-known/openid-configuration";

  private TestOpServer server;

  private TestSupport.MutableClock clock;

  @BeforeEach
  void setUp() throws Exception {
    this.server = new TestOpServer();
    this.clock = new TestSupport.MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
  }

  @AfterEach
  void tearDown() {
    this.server.close();
  }

  private RpConfigurationProperties.ProviderConfig provider(final String issuer) {
    final RpConfigurationProperties.ProviderConfig config = new RpConfigurationProperties.ProviderConfig();
    config.setIssuer(issuer);
    return config;
  }

  private OpRegistry registry(final List<RpConfigurationProperties.ProviderConfig> providers,
      final List<String> blackList) {
    final RpConfigurationProperties.Discovery discovery = new RpConfigurationProperties.Discovery();
    discovery.setBlackList(blackList);
    return new OpRegistry(providers, discovery, this.clock);
  }

  @Test
  void fetchesDiscoveryDocument() {
    final String issuer = this.server.getBaseUrl();
    final JSONObject doc = TestOpServer.discoveryDocument(issuer);
    doc.put("display_name#sv", "Test-OP");
    doc.put("display_name#en", "Test OP");
    doc.put("logo_uri", "https://op.example.com/logo.svg");
    this.server.on(WELL_KNOWN, e -> TestOpServer.Response.json(doc));

    final OpRegistry registry = this.registry(List.of(this.provider(issuer)), List.of());
    assertThat(registry.getProviders()).isEmpty();
    registry.refreshDue();

    assertThat(registry.getProviders()).hasSize(1);
    final OpenIdProvider op = registry.getProvider(issuer);
    assertThat(op).isNotNull();
    assertThat(op.getSource()).isEqualTo(OpenIdProvider.Source.MANUAL);
    assertThat(op.getDisplayNames()).containsEntry("sv", "Test-OP").containsEntry("en", "Test OP");
    assertThat(op.getLogo("sv")).isEqualTo("https://op.example.com/logo.svg");
  }

  @Test
  void rejectsIssuerMismatch() {
    final String issuer = this.server.getBaseUrl();
    this.server.on(WELL_KNOWN, e -> TestOpServer.Response.json(TestOpServer.discoveryDocument(issuer + "/other")));
    final OpRegistry registry = this.registry(List.of(this.provider(issuer)), List.of());
    registry.refreshDue();
    assertThat(registry.getProviders()).isEmpty();
  }

  @Test
  void unreachableOpAppearsWhenItCanBeFetched() {
    final String issuer = this.server.getBaseUrl();
    final AtomicInteger calls = new AtomicInteger();
    final OpRegistry registry = this.registry(List.of(this.provider(issuer)), List.of());

    registry.refreshDue();
    assertThat(registry.getProviders()).isEmpty();

    this.server.on(WELL_KNOWN, e -> {
      calls.incrementAndGet();
      return TestOpServer.Response.json(TestOpServer.discoveryDocument(issuer));
    });

    // Not yet time for a retry
    this.clock.advance(Duration.ofMinutes(4));
    registry.refreshDue();
    assertThat(calls.get()).isZero();
    assertThat(registry.getProviders()).isEmpty();

    // Retry after 5 minutes
    this.clock.advance(Duration.ofMinutes(1));
    registry.refreshDue();
    assertThat(calls.get()).isEqualTo(1);
    assertThat(registry.getProviders()).hasSize(1);

    // Next refresh after an hour
    this.clock.advance(Duration.ofMinutes(59));
    registry.refreshDue();
    assertThat(calls.get()).isEqualTo(1);
    this.clock.advance(Duration.ofMinutes(1));
    registry.refreshDue();
    assertThat(calls.get()).isEqualTo(2);
  }

  @Test
  void failedRefreshKeepsLastDocument() {
    final String issuer = this.server.getBaseUrl();
    this.server.on(WELL_KNOWN, e -> TestOpServer.Response.json(TestOpServer.discoveryDocument(issuer)));
    final OpRegistry registry = this.registry(List.of(this.provider(issuer)), List.of());
    registry.refreshDue();
    assertThat(registry.getProviders()).hasSize(1);

    this.server.on(WELL_KNOWN, e -> new TestOpServer.Response(500, "text/plain", "error"));
    this.clock.advance(Duration.ofHours(1));
    registry.refreshDue();
    assertThat(registry.getProviders()).hasSize(1);
  }

  @Test
  void inlineDocumentIsNotFetched() {
    final String issuer = "https://op.example.com";
    final RpConfigurationProperties.ProviderConfig config = this.provider(issuer);
    config.setDiscoveryDocument(TestOpServer.discoveryDocument(issuer).toJSONString());
    final OpRegistry registry = this.registry(List.of(config), List.of());
    registry.setFetcher(i -> {
      throw new IllegalStateException("Should not fetch");
    });
    assertThat(registry.getProviders()).hasSize(1);
    registry.refreshDue();
    assertThat(registry.getProviders()).hasSize(1);
  }

  @Test
  void resourceDocument() {
    final String issuer = "https://op.example.com";
    final RpConfigurationProperties.ProviderConfig config = this.provider(issuer);
    config.setDiscoveryDocumentResource(new ByteArrayResource(
        TestOpServer.discoveryDocument(issuer).toJSONString().getBytes(StandardCharsets.UTF_8)));
    final OpRegistry registry = this.registry(List.of(config), List.of());
    assertThat(registry.getProvider(issuer)).isNotNull();
  }

  @Test
  void invalidInlineDocumentIsLeftOut() {
    final RpConfigurationProperties.ProviderConfig mismatch = this.provider("https://op1.example.com");
    mismatch.setDiscoveryDocument(TestOpServer.discoveryDocument("https://other.example.com").toJSONString());
    final RpConfigurationProperties.ProviderConfig invalid = this.provider("https://op2.example.com");
    invalid.setDiscoveryDocument("{ not json");
    final OpRegistry registry = this.registry(List.of(mismatch, invalid), List.of());
    assertThat(registry.getProviders()).isEmpty();
  }

  @Test
  void blackListedOpIsNotListed() {
    final String issuer = "https://op.example.com";
    final RpConfigurationProperties.ProviderConfig config = this.provider(issuer);
    config.setDiscoveryDocument(TestOpServer.discoveryDocument(issuer).toJSONString());
    final OpRegistry registry = this.registry(List.of(config), List.of(issuer));
    assertThat(registry.getProviders()).isEmpty();
    assertThat(registry.getProvider(issuer)).isNull();
  }

  @Test
  void backgroundRefreshFetchesWithoutBlockingStart() throws Exception {
    final String issuer = this.server.getBaseUrl();
    this.server.on(WELL_KNOWN, e -> TestOpServer.Response.json(TestOpServer.discoveryDocument(issuer)));
    final OpRegistry registry = new OpRegistry(List.of(this.provider(issuer)),
        new RpConfigurationProperties.Discovery(), java.time.Clock.systemUTC());
    try {
      registry.start();
      final long deadline = System.currentTimeMillis() + 5000;
      while (registry.getProviders().isEmpty() && System.currentTimeMillis() < deadline) {
        Thread.sleep(50);
      }
      assertThat(registry.getProviders()).hasSize(1);
    }
    finally {
      registry.stop();
    }
  }

}
