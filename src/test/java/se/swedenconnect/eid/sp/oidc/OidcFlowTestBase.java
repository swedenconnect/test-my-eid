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

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.eid.sp.controller.ApplicationException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Base class for tests that run the OIDC flows against a {@link TestOidcProvider}.
 */
public abstract class OidcFlowTestBase {

  @Autowired
  protected WebApplicationContext context;

  @Autowired
  protected RelyingParty relyingParty;

  @Autowired
  protected OpRegistry opRegistry;

  protected MockMvc mvc;

  protected MockHttpSession session;

  /**
   * Gets the OP test double.
   *
   * @return the OP
   */
  protected abstract TestOidcProvider op();

  @BeforeEach
  void setUpFlow() throws Exception {
    this.mvc = MockMvcBuilders.webAppContextSetup(this.context).build();
    this.session = new MockHttpSession();
    final TestOidcProvider op = this.op();
    op.clientId = this.relyingParty.getEntityId();
    op.rpSigningKey = (RSAKey) this.relyingParty.getSignJwk();
    op.idTokenCustomizer = b -> {
    };
    op.userInfoCustomizer = b -> {
    };
    op.badIdTokenSignature = false;
    op.unsignedUserInfo = false;
    op.tokenRequestErrors.clear();

    final long deadline = System.currentTimeMillis() + 10000;
    while (this.opRegistry.getProvider(op.getIssuer()) == null && System.currentTimeMillis() < deadline) {
      this.refreshProviders();
      Thread.sleep(50);
    }
    assertThat(this.opRegistry.getProvider(op.getIssuer())).isNotNull();
  }

  /**
   * Refreshes the OP sources.
   */
  protected void refreshProviders() {
    this.opRegistry.refreshDue();
  }

  /**
   * Sends an authentication request to the OP.
   *
   * @param issuer the issuer of the OP
   * @return the request parameters POSTed to the OP
   * @throws Exception for errors
   */
  @SuppressWarnings("unchecked")
  protected Map<String, String> startAuthentication(final String issuer) throws Exception {
    final MvcResult result = this.mvc.perform(post("/oidc/request").session(this.session).param("selectedOp", issuer))
        .andExpect(status().isOk())
        .andReturn();
    final ModelAndView mav = result.getModelAndView();
    assertThat(mav).isNotNull();
    assertThat(mav.getViewName()).isEqualTo("oidc-post-request");
    return (Map<String, String>) mav.getModel().get("parameters");
  }

  /**
   * Parses the Request Object and verifies its signature with the RP key.
   *
   * @param parameters the request parameters
   * @return the Request Object
   * @throws Exception for errors
   */
  protected SignedJWT requestObject(final Map<String, String> parameters) throws Exception {
    final SignedJWT jwt = SignedJWT.parse(parameters.get("request"));
    assertThat(jwt.verify(new RSASSAVerifier((RSAKey) this.relyingParty.getSignJwk()))).isTrue();
    assertThat(jwt.getHeader().getKeyID()).isEqualTo(this.relyingParty.getSignJwk().getKeyID());
    return jwt;
  }

  /**
   * Runs a flow up to the callback: sends the request, lets the OP issue a code and calls the callback.
   *
   * @param path the path that starts the flow
   * @return the callback result
   * @throws Exception for errors
   */
  protected MvcResult runFlow(final String path) throws Exception {
    final Map<String, String> params = path == null
        ? this.startAuthentication(this.op().getIssuer())
        : this.startSignatureApproval();
    final SignedJWT ro = this.requestObject(params);
    final String code = this.op().authorize(ro);
    return this.mvc.perform(get("/oidc/callback").session(this.session)
            .param("code", code)
            .param("state", ro.getJWTClaimsSet().getStringClaim("state")))
        .andReturn();
  }

  /**
   * Sends a signature approval request.
   *
   * @return the request parameters
   * @throws Exception for errors
   */
  @SuppressWarnings("unchecked")
  protected Map<String, String> startSignatureApproval() throws Exception {
    final MvcResult result = this.mvc.perform(post("/oidc/request/sign").session(this.session))
        .andExpect(status().isOk())
        .andReturn();
    return (Map<String, String>) result.getModelAndView().getModel().get("parameters");
  }

  /**
   * Runs an authentication flow that is expected to succeed and returns the result page.
   *
   * @return the result page HTML
   * @throws Exception for errors
   */
  protected String authenticate() throws Exception {
    final MvcResult callback = this.runFlow(null);
    assertThat(callback.getResponse().getRedirectedUrl()).isEqualTo("https://localhost:8443/result");
    return this.resultPage();
  }

  /**
   * Gets the result page.
   *
   * @return the HTML
   * @throws Exception for errors
   */
  protected String resultPage() throws Exception {
    return this.mvc.perform(get("/result").session(this.session)).andExpect(status().isOk()).andReturn()
        .getResponse().getContentAsString();
  }

  /**
   * Runs a flow that is expected to end on the application error page.
   *
   * @param path the path that starts the flow ({@code null} for authentication)
   * @return the exception
   */
  protected ApplicationException expectApplicationError(final String path) {
    final Throwable t = catchThrowable(() -> this.runFlow(path));
    assertThat(t).isNotNull();
    Throwable cause = t;
    while (cause != null && !(cause instanceof ApplicationException)) {
      cause = cause.getCause();
    }
    assertThat(cause).as("Expected ApplicationException but got %s", t).isInstanceOf(ApplicationException.class);
    return (ApplicationException) cause;
  }

}
