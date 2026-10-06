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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.oidc.LoaTrustMarkChecker;
import se.swedenconnect.eid.sp.oidc.OpenIdProvider;
import se.swedenconnect.eid.sp.oidc.TestOpServer;
import se.swedenconnect.eid.sp.oidc.TestSupport;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for the federation components, using local test doubles for the federation endpoints.
 */
class FederationComponentsTest {

  private static final String RP = "https://rp.example.com";

  private static final String OP = "https://op.example.com";

  private TestFederation federation;

  private TestSupport.MutableClock clock;

  private FederationClient client;

  private TrustAnchorResolver resolver;

  @BeforeEach
  void setUp() throws Exception {
    this.federation = new TestFederation();
    this.clock = new TestSupport.MutableClock(Instant.now());
    this.federation.now = this.clock::instant;
    this.client = new FederationClient();
    this.resolver = new TrustAnchorResolver(this.federation.getTrustAnchorId(),
        JWKSet.parse(this.federation.getTrustAnchorJwks()), null, this.client, this.clock);
    this.federation.resolvable.put(OP, () -> opMetadata(OP));
    this.federation.listedOps.add(OP);
  }

  @AfterEach
  void tearDown() {
    this.federation.close();
  }

  private static JSONObject opMetadata(final String issuer) {
    final JSONObject doc = TestOpServer.discoveryDocument(issuer);
    doc.put("display_name#en", "Federated OP");
    doc.put("logo_uri", issuer + "/logo.svg");
    final JSONObject md = new JSONObject();
    md.put("openid_provider", doc);
    return md;
  }

  private FederationOpSource opSource() {
    final RpConfigurationProperties.ListingSource source = new RpConfigurationProperties.ListingSource();
    source.setEntityId(this.federation.getTrustAnchorId());
    return new FederationOpSource(this.resolver, this.client, List.of(source), Duration.ofHours(1),
        Duration.ofMinutes(5), this.clock);
  }

  @Test
  void resolveEndpointIsReadFromVerifiedTrustAnchorConfiguration() throws Exception {
    final TrustAnchorResolver.ResolvedEntity resolved = this.resolver.resolve(OP, "openid_provider");
    assertThat(resolved.metadata()).containsKey("openid_provider");
    assertThat(this.federation.calls).contains("ta-ec", "resolve");
  }

  @Test
  void trustAnchorKeyIsRequiredForTrustAnchorConfiguration() throws Exception {
    // A trust anchor resolver configured with another key does not accept the trust anchor's entity configuration
    final TrustAnchorResolver wrongKey = new TrustAnchorResolver(this.federation.getTrustAnchorId(),
        new JWKSet(this.federation.rogueKey.toPublicJWK()), null, this.client, this.clock);
    assertThatThrownBy(() -> wrongKey.resolve(OP, null))
        .isInstanceOf(FederationClient.FederationException.class)
        .hasMessageContaining("configured trust anchor key");
  }

  @Test
  void resolveResponseMustBeSignedWithTrustAnchorKey() {
    this.federation.rogueResolveSignature = true;
    final TrustAnchorResolver configured = new TrustAnchorResolver(this.federation.getTrustAnchorId(),
        this.resolverKeys(), URI.create(this.federation.getBaseUrl() + "/ta/resolve"), this.client, this.clock);
    assertThatThrownBy(() -> configured.resolve(OP, null))
        .isInstanceOf(FederationClient.FederationException.class)
        .hasMessageContaining("could not be verified");
    // The configured resolve endpoint is used, so the trust anchor's entity configuration is never fetched
    assertThat(this.federation.calls).doesNotContain("ta-ec");
  }

  private JWKSet resolverKeys() {
    try {
      return JWKSet.parse(this.federation.getTrustAnchorJwks());
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  void opsAreListedAndResolved() {
    this.federation.resolvedTrustMarks.put(OP, List.of("https://id.swedenconnect.se/loa/loa3"));
    final FederationOpSource source = this.opSource();
    assertThat(source.getProviders()).isEmpty();
    source.refreshDue();

    assertThat(source.getProviders()).hasSize(1);
    final OpenIdProvider op = source.getProviders().getFirst();
    assertThat(op.getIssuer()).isEqualTo(OP);
    assertThat(op.getEntityId()).isEqualTo(OP);
    assertThat(op.getSource()).isEqualTo(OpenIdProvider.Source.FEDERATION);
    assertThat(op.getDisplayNames()).containsEntry("en", "Federated OP");
    assertThat(op.getLogo("en")).isEqualTo(OP + "/logo.svg");
    assertThat(op.getTrustMarkTypes()).containsExactly("https://id.swedenconnect.se/loa/loa3");
    assertThat(op.getExpiresAt()).isNotNull();
  }

  @Test
  void opLeavesListWhenResolveResponseExpiresWithoutRefresh() {
    this.federation.resolveLifetime = Duration.ofMinutes(90);
    final FederationOpSource source = this.opSource();
    source.refreshDue();
    assertThat(source.getProviders()).hasSize(1);

    // The resolver stops working - the OP is kept until its resolve response expires
    this.federation.rogueResolveSignature = true;
    this.clock.advance(Duration.ofHours(1));
    source.refreshDue();
    assertThat(source.getProviders()).hasSize(1);

    this.clock.advance(Duration.ofMinutes(31));
    source.refreshDue();
    assertThat(source.getProviders()).isEmpty();

    // ... and comes back after a successful resolve
    this.federation.rogueResolveSignature = false;
    this.clock.advance(Duration.ofMinutes(5));
    source.refreshDue();
    assertThat(source.getProviders()).hasSize(1);
  }

  @Test
  void failedResolveIsRetried() {
    this.federation.resolvable.remove(OP);
    final FederationOpSource source = this.opSource();
    source.refreshDue();
    assertThat(source.getProviders()).isEmpty();
    final long resolves = this.federation.calls.stream().filter("resolve"::equals).count();

    this.federation.resolvable.put(OP, () -> opMetadata(OP));
    this.clock.advance(Duration.ofMinutes(4));
    source.refreshDue();
    assertThat(this.federation.calls.stream().filter("resolve"::equals).count()).isEqualTo(resolves);

    this.clock.advance(Duration.ofMinutes(1));
    source.refreshDue();
    assertThat(source.getProviders()).hasSize(1);
  }

  @Test
  void opNoLongerListedIsRemoved() {
    final FederationOpSource source = this.opSource();
    source.refreshDue();
    assertThat(source.getProviders()).hasSize(1);
    this.federation.listedOps.clear();
    this.clock.advance(Duration.ofHours(1));
    source.refreshDue();
    assertThat(source.getProviders()).isEmpty();
  }

  @Test
  void failedListingKeepsOps() {
    final FederationOpSource source = this.opSource();
    source.refreshDue();
    this.federation.listingDown = true;
    this.clock.advance(Duration.ofHours(1));
    source.refreshDue();
    assertThat(source.getProviders()).hasSize(1);
  }

  @Test
  void opWhoseIssuerDiffersFromEntityIdIsRejected() {
    this.federation.resolvable.put(OP, () -> opMetadata("https://other.example.com"));
    final FederationOpSource source = this.opSource();
    source.refreshDue();
    assertThat(source.getProviders()).isEmpty();
  }

  private RpTrustMarkService trustMarkService() {
    final RpConfigurationProperties.TrustMarkIssuer issuer = new RpConfigurationProperties.TrustMarkIssuer();
    issuer.setEntityId(this.federation.getTrustMarkIssuerId());
    issuer.setTrustMarkTypes(List.of("https://id.swedenconnect.se/contract/sc/prepaid-auth-2021"));
    return new RpTrustMarkService(RP, List.of(issuer), this.resolver, this.client, Duration.ofHours(1),
        Duration.ofMinutes(5), this.clock);
  }

  @Test
  void rpTrustMarksAreFetchedAndVerified() throws Exception {
    final RpTrustMarkService service = this.trustMarkService();
    assertThat(service.getTrustMarks()).isEmpty();
    service.refreshDue();
    final List<JSONObject> marks = service.getTrustMarks();
    assertThat(marks).hasSize(1);
    assertThat(marks.getFirst().get("trust_mark_type"))
        .isEqualTo("https://id.swedenconnect.se/contract/sc/prepaid-auth-2021");
    final SignedJWT mark = SignedJWT.parse((String) marks.getFirst().get("trust_mark"));
    assertThat(mark.getJWTClaimsSet().getSubject()).isEqualTo(RP);
  }

  @Test
  void trustMarkIsKeptWhileIssuerIsUnreachableUntilItExpires() {
    this.federation.trustMarkLifetime = Duration.ofHours(4);
    final RpTrustMarkService service = this.trustMarkService();
    service.refreshDue();
    assertThat(service.getTrustMarks()).hasSize(1);

    this.federation.trustMarkIssuerDown = true;
    this.clock.advance(Duration.ofHours(1));
    service.refreshDue();
    assertThat(service.getTrustMarks()).hasSize(1);

    this.clock.advance(Duration.ofHours(3));
    service.refreshDue();
    assertThat(service.getTrustMarks()).isEmpty();

    this.federation.trustMarkIssuerDown = false;
    this.clock.advance(Duration.ofMinutes(5));
    service.refreshDue();
    assertThat(service.getTrustMarks()).hasSize(1);
  }

  @Test
  void trustMarkIsRenewedBeforeItExpires() {
    this.federation.trustMarkLifetime = Duration.ofMinutes(40);
    final RpTrustMarkService service = this.trustMarkService();
    service.refreshDue();
    final long fetches = this.federation.calls.stream().filter("trust-mark"::equals).count();

    // Renewed when half of the lifetime has passed
    this.clock.advance(Duration.ofMinutes(21));
    service.refreshDue();
    assertThat(this.federation.calls.stream().filter("trust-mark"::equals).count()).isEqualTo(fetches + 1);
  }

  @Test
  void trustMarkWithBadSignatureIsRejected() {
    // The issuer's keys come from the trust chain; a trust mark signed by another key is rejected
    final RpConfigurationProperties.TrustMarkIssuer issuer = new RpConfigurationProperties.TrustMarkIssuer();
    issuer.setEntityId(OP);
    issuer.setTrustMarkEndpoint(this.federation.getBaseUrl() + "/tmi/trust-mark");
    issuer.setTrustMarkTypes(List.of("https://id.swedenconnect.se/contract/sc/prepaid-auth-2021"));
    final RpTrustMarkService service = new RpTrustMarkService(RP, List.of(issuer), this.resolver, this.client,
        Duration.ofHours(1), Duration.ofMinutes(5), this.clock);
    service.refreshDue();
    assertThat(service.getTrustMarks()).isEmpty();
  }

  @Test
  void entityConfigurationCarriesAuthorityHintsAndTrustMarks() throws Exception {
    final RpTrustMarkService service = this.trustMarkService();
    service.refreshDue();
    final EntityConfigurationService ec =
        new EntityConfigurationService(TestSupport.relyingParty(), Duration.ofDays(7), this.clock);
    ec.setAuthorityHintsSupplier(() -> List.of("https://im.example.com"));
    ec.setTrustMarksSupplier(service::getTrustMarks);
    final SignedJWT jwt = ec.getEntityConfiguration();
    assertThat(jwt.getJWTClaimsSet().getStringListClaim("authority_hints")).containsExactly("https://im.example.com");
    assertThat(jwt.getJWTClaimsSet().getListClaim("trust_marks")).hasSize(1);
  }

  @Test
  void loaTrustMarkCheck() throws Exception {
    final LoaTrustMarkChecker checker =
        new LoaTrustMarkChecker(RpConfigurationProperties.Federation.defaultLoaTrustMarkRules());
    final JSONObject doc = TestOpServer.discoveryDocument(OP);
    final String tm = "https://id.swedenconnect.se/loa/";
    final String loa = "http://id.elegnamnden.se/loa/1.0/";
    final String sc = "http://id.swedenconnect.se/loa/1.0/";

    final OpenIdProvider loa3Op = new OpenIdProvider(doc, OpenIdProvider.Source.FEDERATION, List.of(tm + "loa3"),
        OP, Instant.now().plusSeconds(60));
    assertThat(checker.hasRequiredTrustMark(loa3Op, loa + "loa3")).isTrue();
    assertThat(checker.hasRequiredTrustMark(loa3Op, loa + "loa4")).isFalse();
    assertThat(checker.hasRequiredTrustMark(loa3Op, sc + "loa3-nonresident")).isFalse();
    assertThat(checker.hasRequiredTrustMark(loa3Op, loa + "eidas-sub")).isFalse();
    // No trust mark needed
    assertThat(checker.hasRequiredTrustMark(loa3Op, sc + "uncertified-loa3")).isTrue();
    assertThat(checker.hasRequiredTrustMark(loa3Op, loa + "loa1")).isTrue();
    assertThat(checker.hasRequiredTrustMark(loa3Op, null)).isTrue();

    final OpenIdProvider nonResident = new OpenIdProvider(doc, OpenIdProvider.Source.FEDERATION,
        List.of(tm + "loa3", tm + "nonresident"), OP, null);
    assertThat(checker.hasRequiredTrustMark(nonResident, sc + "loa3-nonresident")).isTrue();
    assertThat(checker.hasRequiredTrustMark(nonResident, sc + "loa2-nonresident")).isFalse();

    final OpenIdProvider eidas = new OpenIdProvider(doc, OpenIdProvider.Source.FEDERATION, List.of(tm + "eidas"),
        OP, null);
    assertThat(checker.hasRequiredTrustMark(eidas, loa + "eidas-nf-high")).isTrue();

    // No check for manually configured OPs
    final OpenIdProvider manual = new OpenIdProvider(doc, OpenIdProvider.Source.MANUAL, List.of());
    assertThat(checker.hasRequiredTrustMark(manual, loa + "loa4")).isTrue();
  }

  @Test
  void federationSettingsRequireTrustAnchorKey() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getFederation().setEnabled(true);
    props.getFederation().getTrustAnchor().setEntityId("https://ta.example.com");
    assertThatThrownBy(props::afterPropertiesSet)
        .hasMessageContaining("rp.federation.trust-anchor.jwks");

    props.getFederation().getTrustAnchor().setJwks(this.federation.getTrustAnchorJwks());
    props.afterPropertiesSet();
    assertThat(props.getFederation().getEffectiveListingSources()).hasSize(1);
    assertThat(props.getFederation().getEffectiveListingSources().getFirst().getEntityId())
        .isEqualTo("https://ta.example.com");
  }

  @Test
  void federationDisabledNeedsNoTrustAnchor() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.afterPropertiesSet();
    assertThat(props.getFederation().isEnabled()).isFalse();
  }

}
