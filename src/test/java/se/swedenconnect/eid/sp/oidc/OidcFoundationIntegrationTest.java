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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Starts the application without any {@code rp.*} settings and checks the start page, the entity configuration and
 * {@code /oidc/metadata}.
 */
@SpringBootTest
@ActiveProfiles("test")
class OidcFoundationIntegrationTest {

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private se.swedenconnect.eid.sp.config.SpConfigurationProperties spProperties;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    this.mvc = MockMvcBuilders.webAppContextSetup(this.context).build();
  }

  @Test
  void nestedSettingsAreBound() {
    // Regression: Lombok-generated constructors must not switch these classes to constructor binding
    assertThat(this.spProperties.getMetadata().getUiinfo().getDescriptions()).isNotEmpty();
    assertThat(this.spProperties.getUi().getAttributes())
        .anyMatch(a -> a.isAdvanced() && "urn:oid:1.2.752.201.3.7".equals(a.getAttributeName()));
    assertThat(this.spProperties.getUi().getAttributes())
        .anyMatch(a -> "sp.msg.attr.gender.desc".equals(a.getDescriptionMessageCode()));
  }

  @Test
  void federationIsNotRunWhenDisabled() {
    // Nothing is listed, resolved or fetched when federation is disabled
    assertThat(this.context.getBeanNamesForType(se.swedenconnect.eid.sp.oidc.federation.FederationService.class))
        .isEmpty();
  }

  @Test
  void startPageShowsIdps() throws Exception {
    final MvcResult result = this.mvc.perform(get("/")).andExpect(status().isOk()).andReturn();
    final String html = result.getResponse().getContentAsString();
    assertThat(html).contains("https://idp.example.com/idp");
    assertThat(html).contains("SAML");
    assertThat(html).doesNotContain("selectedOp");
  }

  @Test
  void entityConfigurationIsServed() throws Exception {
    final MvcResult result = this.mvc.perform(get("/.well-known/openid-federation"))
        .andExpect(status().isOk())
        .andReturn();
    assertThat(result.getResponse().getContentType()).startsWith("application/entity-statement+jwt");

    final SignedJWT jwt = SignedJWT.parse(result.getResponse().getContentAsString());
    assertThat(jwt.getHeader().getType().getType()).isEqualTo("entity-statement+jwt");
    assertThat(jwt.getHeader().getKeyID()).isNotBlank();

    final Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();
    assertThat(claims.get("iss")).isEqualTo("https://localhost:8443");
    assertThat(claims.get("sub")).isEqualTo("https://localhost:8443");
    assertThat(claims).doesNotContainKeys("authority_hints", "trust_marks");

    final JWKSet jwks = JWKSet.parse(jwt.getJWTClaimsSet().getJSONObjectClaim("jwks"));
    final JWK key = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
    assertThat(key).isNotNull();
    final JWSVerifier verifier = new RSASSAVerifier(key.toRSAKey());
    assertThat(jwt.verify(verifier)).isTrue();

    final Map<String, Object> metadata = jwt.getJWTClaimsSet().getJSONObjectClaim("metadata");
    assertThat(metadata).containsOnlyKeys("openid_relying_party");

    @SuppressWarnings("unchecked")
    final Map<String, Object> rp = (Map<String, Object>) metadata.get("openid_relying_party");
    RpMetadataAssertions.assertMeetsSwedenConnectRequirements(new JSONObject(rp));
    assertThat(rp.get("redirect_uris")).isEqualTo(List.of("https://localhost:8443/oidc/callback"));
    assertThat(rp.get("client_uri")).isEqualTo("https://localhost:8443/");
    assertThat(rp.get("logo_uri")).isEqualTo("https://localhost:8443/images/logo.svg");
    assertThat(rp.get("client_name#sv")).isEqualTo("Testa ditt eID");
    assertThat(rp.get("client_name#en")).isEqualTo("Test your eID");
    assertThat(rp.get("contacts")).isEqualTo(List.of("operations@swedenconnect.se"));
    assertThat(rp.get("organization_name#sv")).isEqualTo("Sweden Connect");
    assertThat(rp.get("organization_identifier")).isEqualTo("urn:glue:iso6523:0007:2021006883");
    assertThat(rp.get("request_object_signing_alg")).isEqualTo("RS512");
    assertThat(rp.get("token_endpoint_auth_signing_alg")).isEqualTo("RS512");
    assertThat(rp.get("subject_type")).isEqualTo("public");
    assertThat(rp).doesNotContainKeys("id_token_encrypted_response_alg", "userinfo_encrypted_response_alg",
        "client_registration_types");
  }

  @Test
  void metadataEndpointHasSameContent() throws Exception {
    final String ec = this.mvc.perform(get("/.well-known/openid-federation")).andReturn()
        .getResponse().getContentAsString();
    final Map<String, Object> metadataClaim = SignedJWT.parse(ec).getJWTClaimsSet().getJSONObjectClaim("metadata");

    final MvcResult result = this.mvc.perform(get("/oidc/metadata")).andExpect(status().isOk()).andReturn();
    assertThat(result.getResponse().getContentType()).startsWith("application/json");
    final Map<String, Object> metadata = JSONObjectUtils.parse(result.getResponse().getContentAsString());
    assertThat(metadata).isEqualTo(metadataClaim);
  }

}
