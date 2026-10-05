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
package se.swedenconnect.eid.sp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import net.minidev.json.JSONValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties;
import se.swedenconnect.eid.sp.model.AttributeInfo;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.model.AuthenticationInfo;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation;
import se.swedenconnect.eid.sp.model.LoaMessages;
import se.swedenconnect.eid.sp.oidc.LoaTrustMarkChecker;
import se.swedenconnect.eid.sp.oidc.OidcAuthentication;
import se.swedenconnect.eid.sp.oidc.OidcAuthenticationResult;
import se.swedenconnect.eid.sp.oidc.OidcRequestFactory;
import se.swedenconnect.eid.sp.oidc.OidcRequestState;
import se.swedenconnect.eid.sp.oidc.OidcResponseProcessor;
import se.swedenconnect.eid.sp.oidc.OpRegistry;
import se.swedenconnect.eid.sp.oidc.OpenIdProvider;
import se.swedenconnect.eid.sp.oidc.RelyingPartyFactory;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Controller for the OpenID Connect flows: authentication and signature approval.
 *
 * @author Martin Lindström
 */
@Controller
@RequestMapping("/oidc")
public class OidcController extends BaseController {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcController.class);

  /** Session attribute for the state of a sent request. */
  public static final @NonNull String REQUEST_STATE_ATTRIBUTE = "oidc-request";

  /** The path for the signature approval request. */
  public static final @NonNull String SIGN_PATH = "/oidc/request/sign";

  /** The OP registry. */
  private final OpRegistry opRegistry;

  /** Creates requests. */
  private final OidcRequestFactory requestFactory;

  /** Processes responses. */
  private final OidcResponseProcessor responseProcessor;

  /** For displaying claims. */
  private final AttributeInfoRegistry attributeInfoRegistry;

  /** Localized messages. */
  private final MessageSource messageSource;

  /** The RP settings. */
  private final RpConfigurationProperties rpProperties;

  /** Checks the OP's LoA trust marks. */
  private final LoaTrustMarkChecker loaTrustMarkChecker;

  /** The application URI (base URI plus context path). */
  private final String applicationUri;

  /**
   * Constructor.
   *
   * @param opRegistry the OP registry
   * @param requestFactory creates requests
   * @param responseProcessor processes responses
   * @param attributeInfoRegistry for displaying claims
   * @param messageSource localized messages
   * @param rpProperties the RP settings
   * @param spProperties the SP settings
   * @param loaTrustMarkChecker checks the OP's LoA trust marks
   * @param contextPath the context path
   */
  public OidcController(final @NonNull OpRegistry opRegistry, final @NonNull OidcRequestFactory requestFactory,
      final @NonNull OidcResponseProcessor responseProcessor,
      final @NonNull AttributeInfoRegistry attributeInfoRegistry, final @NonNull MessageSource messageSource,
      final @NonNull RpConfigurationProperties rpProperties, final @NonNull SpConfigurationProperties spProperties,
      final @NonNull LoaTrustMarkChecker loaTrustMarkChecker,
      @org.springframework.beans.factory.annotation.Value("${server.servlet.context-path:/}")
      final @NonNull String contextPath) {
    this.opRegistry = opRegistry;
    this.requestFactory = requestFactory;
    this.responseProcessor = responseProcessor;
    this.attributeInfoRegistry = attributeInfoRegistry;
    this.messageSource = messageSource;
    this.rpProperties = rpProperties;
    this.loaTrustMarkChecker = loaTrustMarkChecker;
    this.applicationUri = RelyingPartyFactory.applicationUri(spProperties.getBaseUri(), contextPath);
  }

  /**
   * Sends an authentication request to the selected OP.
   *
   * @param request the HTTP request
   * @param selectedOp the issuer of the selected OP
   * @return a model and view that POSTs the request to the OP
   * @throws ApplicationException for errors
   */
  @RequestMapping(value = "/request", method = { RequestMethod.GET, RequestMethod.POST })
  public @NonNull ModelAndView sendRequest(final @NonNull HttpServletRequest request,
      @RequestParam("selectedOp") final @NonNull String selectedOp) throws ApplicationException {

    log.debug("Request for sending OIDC authentication request to '{}' [client-ip-address='{}']",
        selectedOp, request.getRemoteAddr());
    final OpenIdProvider op = this.getProvider(selectedOp);
    try {
      final OidcRequestFactory.OidcRequest oidcRequest = this.requestFactory.createAuthenticationRequest(op);
      return this.post(request.getSession(), oidcRequest);
    }
    catch (final RuntimeException e) {
      log.error("Failed to create OIDC authentication request for '{}' - {}", selectedOp, e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.failed-request", e);
    }
  }

  /**
   * Sends a signature approval request to the OP where the user authenticated.
   *
   * @param request the HTTP request
   * @return a model and view that POSTs the request to the OP
   * @throws ApplicationException for errors
   */
  @RequestMapping(value = "/request/sign", method = { RequestMethod.GET, RequestMethod.POST })
  public @NonNull ModelAndView sendSignatureApprovalRequest(final @NonNull HttpServletRequest request)
      throws ApplicationException {

    final HttpSession session = request.getSession();
    final OidcAuthentication authentication =
        (OidcAuthentication) session.getAttribute(OidcAuthentication.SESSION_ATTRIBUTE);
    if (authentication == null) {
      log.info("No OIDC authentication in session - cannot send signature approval request [client-ip-address='{}']",
          request.getRemoteAddr());
      throw new ApplicationException("sp.msg.error.no-session");
    }
    final OpenIdProvider op = this.getProvider(authentication.issuer());
    if (!op.supportsScope(ScopeConstants.SIGN_APPROVAL.getValue())) {
      throw new ApplicationException("sp.msg.error.failed-request",
          "OP '%s' does not support signature approval".formatted(op.getIssuer()));
    }
    final Locale locale = LocaleContextHolder.getLocale();
    final String signMessage = authentication.givenName() != null
        ? this.messageSource.getMessage("sp.msg.sign-message", new Object[] { authentication.givenName() }, locale)
        : this.messageSource.getMessage("sp.msg.sigm-message-noname", null, locale);
    try {
      return this.post(session,
          this.requestFactory.createSignatureApprovalRequest(op, authentication, signMessage));
    }
    catch (final RuntimeException e) {
      log.error("Failed to create OIDC signature approval request for '{}' - {}", op.getIssuer(), e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.failed-request", e);
    }
  }

  /**
   * Receives the authorization response (for both authentication and signature approval).
   *
   * @param request the HTTP request
   * @param code the authorization code
   * @param state the state
   * @param error the error code
   * @param errorDescription the error description
   * @param iss the issuer (RFC 9207)
   * @return a model and view
   * @throws ApplicationException for errors
   */
  @RequestMapping(value = "/callback", method = { RequestMethod.GET, RequestMethod.POST })
  public @NonNull ModelAndView callback(final @NonNull HttpServletRequest request,
      @RequestParam(value = "code", required = false) final @Nullable String code,
      @RequestParam(value = "state", required = false) final @Nullable String state,
      @RequestParam(value = "error", required = false) final @Nullable String error,
      @RequestParam(value = "error_description", required = false) final @Nullable String errorDescription,
      @RequestParam(value = "iss", required = false) final @Nullable String iss) throws ApplicationException {

    final HttpSession session = request.getSession();
    final OidcRequestState requestState = (OidcRequestState) session.getAttribute(REQUEST_STATE_ATTRIBUTE);
    if (requestState == null) {
      log.info("No OIDC request in session [client-ip-address='{}']", request.getRemoteAddr());
      throw new ApplicationException("sp.msg.error.no-session", "No OIDC request found in session");
    }
    if (state == null || !requestState.state().equals(state)) {
      log.info("OIDC response state does not match request [client-ip-address='{}']", request.getRemoteAddr());
      throw new ApplicationException("sp.msg.error.response-processing", "Invalid state in OIDC response");
    }
    session.removeAttribute(REQUEST_STATE_ATTRIBUTE);

    if (iss != null && !requestState.issuer().equals(iss)) {
      log.info("OIDC response iss '{}' does not equal '{}'", iss, requestState.issuer());
      throw new ApplicationException("sp.msg.error.response-processing", "Invalid iss in OIDC response");
    }

    if (error != null) {
      log.info("Received OIDC error response from '{}': {} - {}", requestState.issuer(), error, errorDescription);
      if ("access_denied".equals(error) && this.isCancel(errorDescription)) {
        return new ModelAndView("redirect:" + this.applicationUri + "/");
      }
      final ModelAndView mav = new ModelAndView("oidc-error");
      mav.addObject("error", error);
      mav.addObject("errorDescription", errorDescription);
      session.setAttribute("sp-result", mav);
      return new ModelAndView("redirect:" + this.applicationUri + "/result");
    }
    if (code == null) {
      throw new ApplicationException("sp.msg.error.response-processing", "No code in OIDC response");
    }

    final OpenIdProvider op = this.getProvider(requestState.issuer());
    final OidcAuthenticationResult result;
    try {
      result = this.responseProcessor.process(op, code, requestState);
    }
    catch (final OidcResponseProcessor.OidcResponseException e) {
      log.info("Error processing OIDC response from '{}' - {}", op.getIssuer(), e.getMessage());
      throw new ApplicationException("sp.msg.error.response-processing", e);
    }

    final ModelAndView mav = new ModelAndView();
    mav.addObject("oidcResult", true);
    mav.addObject("authenticationInfo", this.createAuthenticationInfo(result));
    mav.addObject("ping", false);
    if (!this.loaTrustMarkChecker.hasRequiredTrustMark(op, result.getAcr())) {
      mav.addObject("loaTrustMarkWarning", true);
    }

    if (requestState.isSignatureApproval()) {
      final OidcAuthentication expected = requestState.expectedIdentity();
      if (expected == null || !expected.isIdentityMatch(result)) {
        log.info("Signature approval at '{}' was made by another user than the authentication", op.getIssuer());
        throw new ApplicationException("sp.msg.error.response-processing",
            "You did not use the same eID for signature as for authentication.");
      }
      mav.setViewName("success-sign");
      mav.addObject("signMessage", requestState.signMessage());
    }
    else {
      mav.setViewName("success");
      session.setAttribute(OidcAuthentication.SESSION_ATTRIBUTE, OidcAuthentication.from(result));
      if (op.supportsScope(ScopeConstants.SIGN_APPROVAL.getValue())) {
        mav.addObject("signIdp", new IdpDiscoveryInformation(op, LocaleContextHolder.getLocale().getLanguage())
            .getIdpModel(LocaleContextHolder.getLocale()));
        mav.addObject("pathSign", SIGN_PATH);
      }
    }
    session.setAttribute("sp-result", mav);
    return new ModelAndView("redirect:" + this.applicationUri + "/result");
  }

  /**
   * Stores the request state in the session and returns the view that POSTs the request to the OP.
   *
   * @param session the session
   * @param oidcRequest the request
   * @return a model and view
   */
  private @NonNull ModelAndView post(final @NonNull HttpSession session,
      final OidcRequestFactory.@NonNull OidcRequest oidcRequest) {
    session.setAttribute(REQUEST_STATE_ATTRIBUTE, oidcRequest.state());
    session.removeAttribute("sp-result");
    final ModelAndView mav = new ModelAndView("oidc-post-request");
    mav.addObject("action", oidcRequest.endpoint().toString());
    mav.addObject("parameters", oidcRequest.parameters());
    return mav;
  }

  /**
   * Gets a listed OP.
   *
   * @param issuer the issuer
   * @return the OP
   * @throws ApplicationException if the OP is not listed
   */
  private @NonNull OpenIdProvider getProvider(final @NonNull String issuer) throws ApplicationException {
    final OpenIdProvider op = this.opRegistry.getProvider(issuer);
    if (op == null) {
      log.info("OP '{}' is not available", issuer);
      throw new ApplicationException("sp.msg.error.unknown-op", "Unknown OP " + issuer);
    }
    return op;
  }

  /**
   * Tells whether the error description holds one of the configured cancel terms.
   *
   * @param errorDescription the error description
   * @return {@code true} if the user cancelled
   */
  boolean isCancel(final @Nullable String errorDescription) {
    if (errorDescription == null) {
      return false;
    }
    final String lower = errorDescription.toLowerCase(Locale.ROOT);
    return this.rpProperties.getCancelTerms().stream()
        .anyMatch(t -> !t.isBlank() && lower.contains(t.toLowerCase(Locale.ROOT)));
  }

  /**
   * Creates the model for the result page: the claims with configured labels and the LoA texts.
   *
   * @param result the result
   * @return the model
   */
  private @NonNull AuthenticationInfo createAuthenticationInfo(final @NonNull OidcAuthenticationResult result) {
    final AuthenticationInfo info = new AuthenticationInfo();
    LoaMessages.apply(info, result.getAcr());
    for (final Map.Entry<String, Object> claim : result.getClaims().entrySet()) {
      final AttributeInfo ai = this.attributeInfoRegistry.resolveClaim(claim.getKey(), claimValue(claim.getValue()));
      if (ai == null) {
        continue;
      }
      if (ai.isAdvanced()) {
        info.getAdvancedAttributes().add(ai);
      }
      else {
        info.getAttributes().add(ai);
      }
    }
    info.setAttributes(sorted(info.getAttributes()));
    info.setAdvancedAttributes(sorted(info.getAdvancedAttributes()));
    return info;
  }

  /**
   * Sorts attributes in configured order.
   *
   * @param attributes the attributes
   * @return a sorted list
   */
  private static @NonNull List<AttributeInfo> sorted(final @NonNull List<AttributeInfo> attributes) {
    return attributes.stream().sorted(Comparator.comparing(AttributeInfo::getSortOrder)).toList();
  }

  /**
   * Gets a claim value as a string.
   *
   * @param value the value
   * @return a string
   */
  private static @Nullable String claimValue(final @Nullable Object value) {
    if (value == null || value instanceof String) {
      return (String) value;
    }
    if (value instanceof Map<?, ?> || value instanceof List<?>) {
      return JSONValue.toJSONString(value);
    }
    return value.toString();
  }

}
