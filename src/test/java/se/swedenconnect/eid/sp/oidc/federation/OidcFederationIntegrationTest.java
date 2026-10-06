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

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import se.swedenconnect.eid.sp.oidc.OidcFlowTestBase;
import se.swedenconnect.eid.sp.oidc.OpenIdProvider;
import se.swedenconnect.eid.sp.oidc.TestOidcProvider;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests the RP with OpenID Federation enabled, against local test doubles for the federation endpoints.
 */
@SpringBootTest
@ActiveProfiles("test")
class OidcFederationIntegrationTest extends OidcFlowTestBase {

  private static final TestFederation FEDERATION;

  /** An OP found only through the federation. */
  private static final TestOidcProvider FED_OP;

  /** An OP configured manually that is also found in the federation. */
  private static final TestOidcProvider DUP_OP;

  private static final String TM = "https://id.swedenconnect.se/loa/";

  private static final String RP_TRUST_MARK = "https://id.swedenconnect.se/contract/sc/prepaid-auth-2021";

  static {
    try {
      FEDERATION = new TestFederation();
      FED_OP = new TestOidcProvider();
      DUP_OP = new TestOidcProvider();
      for (final TestOidcProvider op : List.of(FED_OP, DUP_OP)) {
        FEDERATION.listedOps.add(op.getIssuer());
        FEDERATION.resolvable.put(op.getIssuer(), () -> {
          final JSONObject doc = op.discoveryDocument();
          doc.put("display_name#en", op == FED_OP ? "Federated OP" : "Federated Duplicate");
          final JSONObject md = new JSONObject();
          md.put("openid_provider", doc);
          return md;
        });
        // Both OPs only have the LoA 2 trust mark
        FEDERATION.resolvedTrustMarks.put(op.getIssuer(), List.of(TM + "loa2"));
      }
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @DynamicPropertySource
  static void properties(final DynamicPropertyRegistry registry) {
    registry.add("rp.federation.enabled", () -> "true");
    registry.add("rp.credential.federation.jks.store.location", () -> "classpath:metadata-sign.jks");
    registry.add("rp.credential.federation.jks.store.password", () -> "secret");
    registry.add("rp.credential.federation.jks.store.type", () -> "JKS");
    registry.add("rp.credential.federation.jks.key.alias", () -> "mdsign");
    registry.add("rp.credential.federation.jks.key.key-password", () -> "secret");
    registry.add("rp.federation.trust-anchor.entity-id", FEDERATION::getTrustAnchorId);
    registry.add("rp.federation.trust-anchor.jwks", FEDERATION::getTrustAnchorJwks);
    registry.add("rp.federation.authority-hints[0]", () -> "https://im.example.com/im-reg-sc");
    registry.add("rp.federation.trust-mark-issuers[0].entity-id", FEDERATION::getTrustMarkIssuerId);
    registry.add("rp.federation.trust-mark-issuers[0].trust-mark-types[0]", () -> RP_TRUST_MARK);
    registry.add("rp.providers[0].issuer", DUP_OP::getIssuer);
  }

  @AfterAll
  static void stop() throws Exception {
    FED_OP.close();
    DUP_OP.close();
    FEDERATION.close();
  }

  @Autowired
  private FederationService federationService;

  /** The OP used by the flow helpers. */
  private TestOidcProvider current = FED_OP;

  @Override
  protected TestOidcProvider op() {
    return this.current;
  }

  @Override
  protected void refreshProviders() {
    this.opRegistry.refreshDue();
    this.federationService.refreshDue();
  }

  @BeforeEach
  void refreshFederation() throws Exception {
    final long deadline = System.currentTimeMillis() + 10000;
    while (System.currentTimeMillis() < deadline
        && (this.opRegistry.getProvider(FED_OP.getIssuer()) == null
        || this.federationService.getTrustMarkService().getTrustMarks().isEmpty())) {
      this.federationService.refreshDue();
      Thread.sleep(50);
    }
    for (final TestOidcProvider op : List.of(FED_OP, DUP_OP)) {
      op.clientId = this.relyingParty.getEntityId();
      op.rpSigningKey = (RSAKey) this.relyingParty.getSignJwk();
    }
  }

  @Test
  void federationOpsAreListed() throws Exception {
    final String html = this.mvc.perform(get("/")).andReturn().getResponse().getContentAsString();
    assertThat(html).contains("Federated OP").contains("value=\"" + FED_OP.getIssuer() + "\"");

    // The manually configured OP is shown once, from the manual configuration
    assertThat(html).doesNotContain("Federated Duplicate");
    assertThat(html.split("value=\"" + DUP_OP.getIssuer() + "\"", -1)).hasSize(2);
    final OpenIdProvider dup = this.opRegistry.getProvider(DUP_OP.getIssuer());
    assertThat(dup).isNotNull();
    assertThat(dup.getSource()).isEqualTo(OpenIdProvider.Source.MANUAL);

    final OpenIdProvider fed = this.opRegistry.getProvider(FED_OP.getIssuer());
    assertThat(fed).isNotNull();
    assertThat(fed.getSource()).isEqualTo(OpenIdProvider.Source.FEDERATION);
    assertThat(fed.getTrustMarkTypes()).containsExactly(TM + "loa2");
  }

  @Test
  void entityConfigurationHasAuthorityHintsAndTrustMarks() throws Exception {
    final String ec = this.mvc.perform(get("/.well-known/openid-federation")).andReturn().getResponse()
        .getContentAsString();
    final SignedJWT jwt = SignedJWT.parse(ec);
    final JWTClaimsSet claims = jwt.getJWTClaimsSet();
    assertThat(claims.getStringListClaim("authority_hints")).containsExactly("https://im.example.com/im-reg-sc");
    final List<Object> marks = claims.getListClaim("trust_marks");
    assertThat(marks).hasSize(1);
    @SuppressWarnings("unchecked")
    final Map<String, Object> mark = (Map<String, Object>) marks.getFirst();
    assertThat(mark.get("trust_mark_type")).isEqualTo(RP_TRUST_MARK);

    // Signed with the federation key, which is not the OIDC signing key
    final JWKSet jwks = JWKSet.parse(claims.getJSONObjectClaim("jwks"));
    assertThat(jwks.getKeys()).hasSize(1);
    assertThat(jwks.getKeys().getFirst().getKeyID()).isNotEqualTo(this.relyingParty.getSignJwk().getKeyID());
    assertThat(jwt.verify(new RSASSAVerifier(jwks.getKeys().getFirst().toRSAKey()))).isTrue();

    @SuppressWarnings("unchecked")
    final Map<String, Object> rp = (Map<String, Object>) claims.getJSONObjectClaim("metadata")
        .get("openid_relying_party");
    assertThat(rp.get("client_registration_types")).isEqualTo(List.of("automatic"));
    assertThat(claims.getJSONObjectClaim("metadata")).containsOnlyKeys("openid_relying_party");
  }

  @Test
  void requestToFederationOpUsesAutomaticRegistration() throws Exception {
    this.current = FED_OP;
    final Map<String, String> params = this.startAuthentication(FED_OP.getIssuer());
    assertThat(params.get("client_id")).isEqualTo(this.relyingParty.getEntityId());
    final JWTClaimsSet claims = this.requestObject(params).getJWTClaimsSet();
    assertThat(claims.getAudience()).containsExactly(FED_OP.getIssuer());
    assertThat(claims.getIssuer()).isEqualTo(this.relyingParty.getEntityId());
    assertThat(claims.getStringClaim("client_id")).isEqualTo(this.relyingParty.getEntityId());
    assertThat(claims.getSubject()).isNull();
    assertThat(claims.getJWTID()).isNotBlank();
    assertThat(claims.getExpirationTime()).isNotNull();
  }

  @Test
  void loaWarningForFederationOp() throws Exception {
    this.current = FED_OP;
    FED_OP.acr = "http://id.elegnamnden.se/loa/1.0/loa3";
    final String html = this.authenticate();
    assertThat(html).contains("197705232382");
    assertThat(html).contains("does not hold the trust mark");
  }

  @Test
  void noLoaWarningWhenTrustMarkIsHeld() throws Exception {
    this.current = FED_OP;
    FED_OP.acr = "http://id.elegnamnden.se/loa/1.0/loa2";
    try {
      final String html = this.authenticate();
      assertThat(html).doesNotContain("does not hold the trust mark");
    }
    finally {
      FED_OP.acr = "http://id.elegnamnden.se/loa/1.0/loa3";
    }
  }

  @Test
  void noLoaWarningForManualOp() throws Exception {
    this.current = DUP_OP;
    DUP_OP.acr = "http://id.elegnamnden.se/loa/1.0/loa3";
    final String html = this.authenticate();
    assertThat(html).contains("197705232382");
    assertThat(html).doesNotContain("does not hold the trust mark");
  }

}
