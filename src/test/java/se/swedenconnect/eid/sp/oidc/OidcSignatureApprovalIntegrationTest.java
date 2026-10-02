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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import se.swedenconnect.eid.sp.controller.ApplicationException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Tests the OIDC signature approval flow.
 */
@SpringBootTest
@ActiveProfiles("test")
class OidcSignatureApprovalIntegrationTest extends OidcFlowTestBase {

  private static final TestOidcProvider OP;

  private static final Map<String, Object> DEFAULT_USER;

  static {
    try {
      OP = new TestOidcProvider();
      OP.scopesSupported = List.of("openid", "https://id.oidc.se/scope/naturalPersonInfo",
          "https://id.oidc.se/scope/naturalPersonNumber", "https://id.oidc.se/scope/signApproval");
      DEFAULT_USER = OP.userClaims;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @DynamicPropertySource
  static void properties(final DynamicPropertyRegistry registry) {
    registry.add("rp.providers[0].issuer", OP::getIssuer);
  }

  @AfterAll
  static void stop() throws Exception {
    OP.close();
  }

  @AfterEach
  void reset() {
    OP.userClaims = DEFAULT_USER;
  }

  @Override
  protected TestOidcProvider op() {
    return OP;
  }

  @Test
  void signatureStepIsOffered() throws Exception {
    final String html = this.authenticate();
    assertThat(html).contains("/oidc/request/sign").contains("Sign using");
  }

  @Test
  void signatureApprovalRequest() throws Exception {
    this.authenticate();
    final Map<String, String> params = this.startSignatureApproval();
    assertThat(params.get("scope")).isEqualTo("openid https://id.oidc.se/scope/signApproval "
        + "https://id.oidc.se/scope/naturalPersonInfo https://id.oidc.se/scope/naturalPersonNumber");

    final JWTClaimsSet claims = this.requestObject(params).getJWTClaimsSet();
    assertThat(claims.getStringClaim("scope")).isEqualTo(params.get("scope"));
    assertThat(claims.getStringClaim("prompt")).isEqualTo("login consent");
    assertThat(claims.getClaims()).doesNotContainKey("acr_values");
    assertThat(claims.getStringClaim("state")).isNotBlank();
    assertThat(claims.getStringClaim("nonce")).isNotBlank();
    assertThat(claims.getStringClaim("code_challenge_method")).isEqualTo("S256");
    assertThat(claims.getClaims()).containsKey("https://id.oidc.se/param/userMessage");

    final Map<String, Object> signRequest = claims.getJSONObjectClaim("https://id.oidc.se/param/signRequest");
    assertThat(signRequest).containsOnlyKeys("sign_message");
    @SuppressWarnings("unchecked")
    final Map<String, Object> signMessage = (Map<String, Object>) signRequest.get("sign_message");
    assertThat(signMessage.get("mime_type")).isEqualTo("text/plain");
    assertThat(signMessage.get("message")).isEqualTo("Hello Frida! This is a test signature.");

    final Map<String, Object> claimsParameter = claims.getJSONObjectClaim("claims");
    @SuppressWarnings("unchecked")
    final Map<String, Object> idToken = (Map<String, Object>) claimsParameter.get("id_token");
    assertThat(idToken.get("https://id.oidc.se/claim/personalIdentityNumber"))
        .isEqualTo(Map.of("essential", true, "value", "197705232382"));
    assertThat(idToken.get("acr"))
        .isEqualTo(Map.of("essential", true, "value", "http://id.elegnamnden.se/loa/1.0/loa3"));
    assertThat(idToken).doesNotContainKey("https://id.oidc.se/claim/coordinationNumber");
  }

  @Test
  void coordinationNumberBinding() throws Exception {
    OP.userClaims = Map.of("https://id.oidc.se/claim/coordinationNumber", "197010632391", "given_name", "Sam");
    this.authenticate();
    final JWTClaimsSet claims = this.requestObject(this.startSignatureApproval()).getJWTClaimsSet();
    @SuppressWarnings("unchecked")
    final Map<String, Object> idToken = (Map<String, Object>) claims.getJSONObjectClaim("claims").get("id_token");
    assertThat(idToken.get("https://id.oidc.se/claim/coordinationNumber"))
        .isEqualTo(Map.of("essential", true, "value", "197010632391"));
    assertThat(idToken).doesNotContainKey("https://id.oidc.se/claim/personalIdentityNumber");
  }

  @Test
  void successfulSignatureApproval() throws Exception {
    this.authenticate();
    final Object authentication = this.session.getAttribute(OidcAuthentication.SESSION_ATTRIBUTE);

    final MvcResult callback = this.runFlow("sign");
    assertThat(callback.getResponse().getRedirectedUrl()).isEqualTo("https://localhost:8443/result");
    final String html = this.resultPage();
    assertThat(html).contains("Hello Frida! This is a test signature.");
    assertThat(html).contains("197705232382");
    // No new signature step on the signature result page
    assertThat(html).doesNotContain("/oidc/request/sign");

    // The signature approval does not replace the stored authentication
    assertThat(this.session.getAttribute(OidcAuthentication.SESSION_ATTRIBUTE)).isSameAs(authentication);
  }

  @Test
  void responseForAnotherUser() throws Exception {
    this.authenticate();
    OP.userClaims = Map.of("https://id.oidc.se/claim/personalIdentityNumber", "198001012384", "given_name", "Other");
    final ApplicationException e = this.expectApplicationError("sign");
    assertThat(e.getMessageCode()).isEqualTo("sp.msg.error.response-processing");
  }

  @Test
  void noAuthenticationInSession() {
    final Throwable t = catchThrowable(() -> this.mvc.perform(post("/oidc/request/sign").session(this.session)));
    assertThat(t).hasRootCauseInstanceOf(ApplicationException.class);
  }

}
