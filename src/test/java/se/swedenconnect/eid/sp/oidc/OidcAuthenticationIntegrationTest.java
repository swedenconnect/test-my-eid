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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.eid.sp.controller.ApplicationException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests the OIDC authentication flow.
 */
@SpringBootTest(properties = "rp.cancel-terms=cancel,avbröt,user aborted")
@ActiveProfiles("test")
class OidcAuthenticationIntegrationTest extends OidcFlowTestBase {

  private static final TestOidcProvider OP;

  static {
    try {
      OP = new TestOidcProvider();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @DynamicPropertySource
  static void properties(final DynamicPropertyRegistry registry) {
    // All list entries must come from the same property source
    registry.add("rp.providers[0].issuer", OP::getIssuer);
    registry.add("rp.providers[1].issuer", () -> "https://op1.example.com");
    registry.add("rp.providers[1].discovery-document-resource", () -> "classpath:test-ops/op1.json");
    registry.add("rp.providers[2].issuer", () -> "https://op5.example.com");
    registry.add("rp.providers[2].discovery-document-resource", () -> "classpath:test-ops/op5.json");
  }

  @AfterAll
  static void stop() throws Exception {
    OP.close();
  }

  @Override
  protected TestOidcProvider op() {
    return OP;
  }

  @Test
  void requestFollowsDiscoveryDocument() throws Exception {
    final Map<String, String> params = this.startAuthentication(OP.getIssuer());
    assertThat(params).containsOnlyKeys("response_type", "client_id", "scope", "request");
    assertThat(params.get("response_type")).isEqualTo("code");
    assertThat(params.get("client_id")).isEqualTo("https://localhost:8443");
    assertThat(params.get("scope")).isEqualTo(
        "openid https://id.oidc.se/scope/naturalPersonInfo https://id.oidc.se/scope/naturalPersonNumber");

    final SignedJWT ro = this.requestObject(params);
    assertThat(ro.getHeader().getAlgorithm().getName()).isEqualTo("RS512");
    final JWTClaimsSet claims = ro.getJWTClaimsSet();
    assertThat(claims.getIssuer()).isEqualTo("https://localhost:8443");
    assertThat(claims.getAudience()).containsExactly(OP.getIssuer());
    assertThat(claims.getStringClaim("client_id")).isEqualTo("https://localhost:8443");
    assertThat(claims.getJWTID()).isNotBlank();
    assertThat(claims.getExpirationTime()).isNotNull();
    assertThat(claims.getStringClaim("response_type")).isEqualTo("code");
    assertThat(claims.getStringClaim("scope")).isEqualTo(params.get("scope"));
    assertThat(claims.getStringClaim("redirect_uri")).isEqualTo("https://localhost:8443/oidc/callback");
    assertThat(claims.getStringClaim("prompt")).isEqualTo("login");
    assertThat(claims.getStringClaim("acr_values")).isEqualTo(
        "http://id.elegnamnden.se/loa/1.0/loa3 http://id.swedenconnect.se/loa/1.0/uncertified-loa3");
    // state: at least 128 bits of entropy (base64url, 22 characters)
    assertThat(claims.getStringClaim("state")).hasSizeGreaterThanOrEqualTo(22);
    assertThat(claims.getStringClaim("nonce")).isNotBlank();
    assertThat(claims.getStringClaim("code_challenge")).isNotBlank();
    assertThat(claims.getStringClaim("code_challenge_method")).isEqualTo("S256");
    assertThat(claims.getClaims()).doesNotContainKeys("claims", "https://id.oidc.se/param/signRequest");

    final Map<String, Object> userMessage = claims.getJSONObjectClaim("https://id.oidc.se/param/userMessage");
    assertThat(userMessage.get("mime_type")).isEqualTo("text/plain");
    assertThat((String) userMessage.get("message#sv")).startsWith("Testa mitt eID");
    assertThat((String) userMessage.get("message#en")).startsWith("Test my eID").doesNotContain("**");

    final ModelAndView mav = this.mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
        .post("/oidc/request").session(this.session).param("selectedOp", OP.getIssuer())).andReturn()
        .getModelAndView();
    assertThat(mav.getModel().get("action")).isEqualTo(OP.getIssuer() + "/authorize");
  }

  @Test
  void requestWithoutAcrValuesOrIdentityScopes() throws Exception {
    final Map<String, String> params = this.startAuthentication("https://op1.example.com");
    assertThat(params.get("scope")).isEqualTo("openid");
    final JWTClaimsSet claims = this.requestObject(params).getJWTClaimsSet();
    assertThat(claims.getClaims()).doesNotContainKeys("acr_values", "https://id.oidc.se/param/userMessage");
  }

  @Test
  void markdownUserMessage() throws Exception {
    final Map<String, String> params = this.startAuthentication("https://op5.example.com");
    assertThat(params.get("scope")).isEqualTo("openid https://id.oidc.se/scope/naturalPersonNumber");
    final Map<String, Object> userMessage =
        this.requestObject(params).getJWTClaimsSet().getJSONObjectClaim("https://id.oidc.se/param/userMessage");
    assertThat(userMessage.get("mime_type")).isEqualTo("text/markdown");
    assertThat((String) userMessage.get("message#sv")).startsWith("# Testa mitt eID");
  }

  @Test
  void unknownOp() throws Exception {
    final Throwable t = org.assertj.core.api.Assertions.catchThrowable(() -> this.startAuthentication(
        "https://unknown.example.com"));
    assertThat(t).hasRootCauseInstanceOf(ApplicationException.class);
  }

  @Test
  void successfulAuthentication() throws Exception {
    final String html = this.authenticate();
    assertThat(OP.tokenRequestErrors).isEmpty();
    assertThat(html).contains("Personal identity number").contains("197705232382");
    assertThat(html).contains("Given name").contains("Frida");
    assertThat(html).contains("Kranstege");
    assertThat(html).contains("Your authentication was performed according to assurance level 3.");
    // Unknown claims (sub, auth_time) are not shown
    assertThat(html).doesNotContain("user-1");
    // The OP does not support signApproval
    assertThat(html).doesNotContain("/oidc/request/sign");

    final OidcAuthentication authn =
        (OidcAuthentication) this.session.getAttribute(OidcAuthentication.SESSION_ATTRIBUTE);
    assertThat(authn).isNotNull();
    assertThat(authn.issuer()).isEqualTo(OP.getIssuer());
    assertThat(authn.personalIdentityNumber()).isEqualTo("197705232382");
    assertThat(authn.givenName()).isEqualTo("Frida");
    assertThat(authn.acr()).isEqualTo("http://id.elegnamnden.se/loa/1.0/loa3");
  }

  @Test
  void claimsFromUserInfoAreMerged() throws Exception {
    OP.idTokenCustomizer = b -> b.claim("given_name", null).claim("birthdate", null);
    OP.userInfoCustomizer = b -> b.claim("email", "frida@example.com");
    final String html = this.authenticate();
    assertThat(html).contains("Frida").contains("frida@example.com");
  }

  @Test
  void wrongState() throws Exception {
    final Map<String, String> params = this.startAuthentication(OP.getIssuer());
    final String code = OP.authorize(this.requestObject(params));
    final Throwable t = org.assertj.core.api.Assertions.catchThrowable(() ->
        this.mvc.perform(get("/oidc/callback").session(this.session).param("code", code).param("state", "wrong")));
    assertThat(t).hasRootCauseInstanceOf(ApplicationException.class);
  }

  @Test
  void badIdTokenSignature() {
    OP.badIdTokenSignature = true;
    assertThat(this.expectApplicationError(null).getMessageCode()).isEqualTo("sp.msg.error.response-processing");
  }

  @Test
  void wrongNonce() {
    OP.idTokenCustomizer = b -> b.claim("nonce", "wrong");
    assertThat(this.expectApplicationError(null).getCause()).hasMessageContaining("nonce");
  }

  @Test
  void wrongAudience() {
    OP.idTokenCustomizer = b -> b.audience("https://other.example.com");
    assertThat(this.expectApplicationError(null).getCause()).hasMessageContaining("aud");
  }

  @Test
  void missingAuthTime() {
    OP.idTokenCustomizer = b -> b.claim("auth_time", null);
    assertThat(this.expectApplicationError(null).getCause()).hasMessageContaining("auth_time");
  }

  @Test
  void unsignedUserInfo() {
    OP.unsignedUserInfo = true;
    assertThat(this.expectApplicationError(null).getCause()).hasMessageContaining("not signed");
  }

  @Test
  void userInfoSubMismatch() {
    OP.userInfoCustomizer = b -> b.subject("user-2");
    assertThat(this.expectApplicationError(null).getCause()).hasMessageContaining("sub");
  }

  @Test
  void cancel() throws Exception {
    final Map<String, String> params = this.startAuthentication(OP.getIssuer());
    final String state = this.requestObject(params).getJWTClaimsSet().getStringClaim("state");
    final MvcResult result = this.mvc.perform(get("/oidc/callback").session(this.session)
        .param("error", "access_denied").param("error_description", "User Aborted the operation")
        .param("state", state)).andReturn();
    assertThat(result.getResponse().getRedirectedUrl()).isEqualTo("https://localhost:8443/");
  }

  @Test
  void cancelSwedish() throws Exception {
    final Map<String, String> params = this.startAuthentication(OP.getIssuer());
    final String state = this.requestObject(params).getJWTClaimsSet().getStringClaim("state");
    final MvcResult result = this.mvc.perform(get("/oidc/callback").session(this.session)
        .param("error", "access_denied").param("error_description", "Användaren AVBRÖT")
        .param("state", state)).andReturn();
    assertThat(result.getResponse().getRedirectedUrl()).isEqualTo("https://localhost:8443/");
  }

  @Test
  void errorResponse() throws Exception {
    for (final List<String> error : List.of(List.of("access_denied", "Not allowed"),
        List.of("login_required", "No session"))) {
      final Map<String, String> params = this.startAuthentication(OP.getIssuer());
      final String state = this.requestObject(params).getJWTClaimsSet().getStringClaim("state");
      final MvcResult result = this.mvc.perform(get("/oidc/callback").session(this.session)
          .param("error", error.get(0)).param("error_description", error.get(1))
          .param("state", state)).andReturn();
      assertThat(result.getResponse().getRedirectedUrl()).isEqualTo("https://localhost:8443/result");
      final String html = this.resultPage();
      assertThat(html).contains("We received an error from the OpenID Provider")
          .contains(error.get(0)).contains(error.get(1));
    }
  }

  @Test
  void callbackWithoutSession() {
    final Throwable t = org.assertj.core.api.Assertions.catchThrowable(() ->
        this.mvc.perform(get("/oidc/callback").param("code", "x").param("state", "y")));
    assertThat(t).hasRootCauseInstanceOf(ApplicationException.class);
  }

}
