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
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.eid.sp.config.EntityID;
import se.swedenconnect.eid.sp.model.AttributeInfo;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.model.AuthenticationInfo;
import se.swedenconnect.eid.sp.model.ErrorStatusInfo;
import se.swedenconnect.eid.sp.model.LastAuthentication;
import se.swedenconnect.eid.sp.model.LoaMessages;
import se.swedenconnect.eid.sp.saml.HokSupport;
import se.swedenconnect.eid.sp.saml.TestMyEidAuthnRequestGenerator;
import se.swedenconnect.eid.sp.saml.TestMyEidAuthnRequestGeneratorContext;
import se.swedenconnect.eid.sp.utils.ClientCertificateGetter;
import se.swedenconnect.opensaml.common.validation.CoreValidatorParameters;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext.HokRequirement;
import se.swedenconnect.opensaml.saml2.request.RequestGenerationException;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingException;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingInput;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.ResponseStatusErrorException;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for creating SAML {@code AuthnRequest} messages and for processing SAML responses.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Controller
@RequestMapping("/saml2")
public class SamlController extends BaseController {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(SamlController.class);

  /** For generating a SAML AuthnRequest message. */
  @Autowired
  @Qualifier("spAuthnRequestGenerator")
  private TestMyEidAuthnRequestGenerator spAuthnRequestGenerator;

  /** For generating a SAML AuthnRequest message for the signature service. */
  @Autowired
  @Qualifier("signSpAuthnRequestGenerator")
  private TestMyEidAuthnRequestGenerator signSpAuthnRequestGenerator;

  /** For processing SAML responses. */
  @Autowired
  private ResponseProcessor responseProcessor;

  @Autowired
  @Qualifier("DebugFlag")
  private Boolean debugFlag;

  /** Is Holder-of-key active? */
  @Autowired
  @Qualifier("hokActive")
  private Boolean hokActive;

  /** The SP entity ID. */
  @Autowired
  @Qualifier("spEntityID")
  private EntityID spEntityID;

  /** The entityID for the sign service SP. */
  @Autowired
  @Qualifier("signSpEntityID")
  private EntityID signSpEntityID;

  @Autowired
  @Qualifier("spMetadata")
  private EntityDescriptor spMetadata;

  @Autowired
  @Qualifier("signSpMetadata")
  private EntityDescriptor signSpMetadata;

  /** For displaying of SAML attributes. */
  @Autowired
  private AttributeInfoRegistry attributeInfoRegistry;

  /** Holds localized messages. */
  @Autowired
  private MessageSource messageSource;

  /** Gets the client TLS certificate (if available). */
  @Autowired
  private ClientCertificateGetter clientCertificateGetter;

  @Autowired
  @Qualifier("userMessages")
  private @NonNull Map<String, String> userMessages;

  @Value("${server.servlet.context-path}")
  private @NonNull String contextPath;

  @Value("${sp.base-uri}")
  private @NonNull String baseUri;

  @Value("${sp.debug-base-uri:}")
  private @Nullable String debugBaseUri;

  /**
   * Builds an {@code AuthnRequest}.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param selectedIdp the selected IdP
   * @param country optional parameter for direct requests to an eIDAS country
   * @param ping whether this is an eIDAS ping request
   * @param useHok whether Holder-of-key should be used ({@code null} if not decided yet)
   * @return a model and view object
   * @throws ApplicationException for errors
   */
  @RequestMapping("/request")
  public @NonNull ModelAndView sendRequest(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      @RequestParam("selectedIdp") final @NonNull String selectedIdp,
      @RequestParam(value = "country", required = false) final @Nullable String country,
      @RequestParam(value = "ping", required = false, defaultValue = "false") final @NonNull Boolean ping,
      @RequestParam(value = "useHok", required = false) final @Nullable Boolean useHok) throws ApplicationException {

    log.debug("Request for generating an AuthnRequest to '{}' [client-ip-address='{}', country='{}']",
        selectedIdp, request.getRemoteAddr(), country);

    // Special handling for Holder-of-key
    //
    HokRequirement hokRequirement = HokRequirement.DONT_USE;
    if (useHok == null && this.hokActive && (country == null || ping)) {
      final HokSupport hokSupport = this.spAuthnRequestGenerator.getIdpHokSupport(selectedIdp);
      if (HokSupport.BOTH == hokSupport) {
        // Ask whether to use HoK or not ...
        final ModelAndView mav = new ModelAndView("ask-hok");
        mav.addObject("selectedIdp", selectedIdp);
        return mav;
      }
      else if (HokSupport.ONLY_HOK == hokSupport) {
        hokRequirement = HokRequirement.REQUIRED;
      }
    }
    else if (useHok != null) {
      hokRequirement = useHok ? HokRequirement.REQUIRED : HokRequirement.DONT_USE;
    }

    try {
      final HttpSession session = request.getSession();

      final TestMyEidAuthnRequestGeneratorContext input = new TestMyEidAuthnRequestGeneratorContext(hokRequirement);
      input.setCountry(country);
      input.setPing(ping);
      input.setDebug(this.debugFlag);
      input.setUserMessages(this.userMessages);

      final RequestHttpObject<AuthnRequest> authnRequest =
          this.spAuthnRequestGenerator.generateAuthnRequest(selectedIdp, null, input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.setAttribute("ping", ping);
      session.removeAttribute("sp-result");
      session.removeAttribute("last-authentication");

      if (SAMLConstants.POST_METHOD.equals(authnRequest.getMethod())) {
        final ModelAndView mav = new ModelAndView("post-request");
        mav.addObject("action", authnRequest.getSendUrl());
        mav.addAllObjects(authnRequest.getRequestParameters());
        return mav;
      }
      else {
        return new ModelAndView("redirect:" + authnRequest.getSendUrl());
      }
    }
    catch (final RequestGenerationException e) {
      log.error("Failed to generate AuthnRequest - {}", e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.failed-request", e);
    }
  }

  /**
   * Controller method that is invoked when the user wants to use his or hers eID to "sign", i.e., to send an
   * {@code AuthnRequest} from the Test my eID signature service SP.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @return a model and view object
   * @throws ApplicationException for errors (session errors)
   */
  @RequestMapping("/request/next")
  public @NonNull ModelAndView sendNextRequest(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response)
      throws ApplicationException {

    final HttpSession session = request.getSession();
    final LastAuthentication lastAuthentication = (LastAuthentication) session.getAttribute("last-authentication");
    if (lastAuthentication == null) {
      log.error("There is no session information available about the last authentication - cannot sign");
      throw new ApplicationException("sp.msg.error.no-session");
    }
    return this.sendSignRequest(request, response, lastAuthentication.getIdp(),
        lastAuthentication.getPersonalIdentityNumber(), lastAuthentication.getPrid(), lastAuthentication.getGivenName(),
        lastAuthentication.getAuthnContextUri(), lastAuthentication.isHokUsed());
  }

  /**
   * Controller method for sending a request to force signature behaviour at the IdP.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param idp the IdP entityID
   * @param personalIdentityNumber the personal identity number (optional)
   * @param prid the PRID (optional)
   * @param givenName the user given name (optional)
   * @param loa the level of assurance (sig-message URI), optional
   * @param hokUsed whether Holder-of-key was used for the authentication
   * @return a model and view object
   * @throws ApplicationException for errors
   */
  @RequestMapping("/request/sign")
  public @NonNull ModelAndView sendSignRequest(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      @RequestParam("idp") final @NonNull String idp,
      @RequestParam(value = "pnr", required = false) final @Nullable String personalIdentityNumber,
      @RequestParam(value = "prid", required = false) final @Nullable String prid,
      @RequestParam(value = "givenName", required = false) final @Nullable String givenName,
      @RequestParam(value = "loa", required = false) final @Nullable String loa,
      @RequestParam(value = "hok", required = false, defaultValue = "false") final @NonNull Boolean hokUsed)
      throws ApplicationException {

    log.debug(
        "Request for generating an AuthnRequest for a signature authentication to '{}' [client-ip-address='{}', personal-number='{}']",
        idp, request.getRemoteAddr(), personalIdentityNumber);

    try {
      final HttpSession session = request.getSession();

      final TestMyEidAuthnRequestGeneratorContext input = new TestMyEidAuthnRequestGeneratorContext(
          hokUsed ? HokRequirement.REQUIRED : HokRequirement.DONT_USE);
      input.setDebug(this.debugFlag);
      input.setPersonalIdentityNumberHint(personalIdentityNumber);
      input.setPridHint(prid);
      input.setRequestedAuthnContextUris(Collections.singletonList(loa));
      input.setUserMessages(this.userMessages);

      // Load signature message ...
      //
      final String signMessage = givenName != null
          ? this.messageSource.getMessage("sp.msg.sign-message", new Object[] { givenName },
          LocaleContextHolder.getLocale())
          : this.messageSource.getMessage("sp.msg.sigm-message-noname", null, LocaleContextHolder.getLocale());

      input.setSignMessage(signMessage);
      session.setAttribute("sign-message", signMessage);

      final RequestHttpObject<AuthnRequest> authnRequest =
          this.signSpAuthnRequestGenerator.generateAuthnRequest(idp, null, input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.removeAttribute("sp-result");

      if (SAMLConstants.POST_METHOD.equals(authnRequest.getMethod())) {
        final ModelAndView mav = new ModelAndView("post-request");
        mav.addObject("action", authnRequest.getSendUrl());
        mav.addAllObjects(authnRequest.getRequestParameters());
        return mav;
      }
      else {
        return new ModelAndView("redirect:" + authnRequest.getSendUrl());
      }
    }
    catch (final RequestGenerationException e) {
      log.error("Failed to generate AuthnRequest for signature - {}", e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.failed-request", e);
    }
  }

  /**
   * Endpoint for receiving and processing SAML responses.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param samlResponse the base64-encoded SAML response
   * @param relayState the relay state
   * @return a model and view
   * @throws ApplicationException for application errors
   */
  @PostMapping("/post")
  public @NonNull ModelAndView processResponse(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      @RequestParam("SAMLResponse") final @NonNull String samlResponse,
      @RequestParam(value = "RelayState", required = false) final @Nullable String relayState)
      throws ApplicationException {

    return this.processResponse(request, response, false, false, samlResponse, relayState);
  }

  /**
   * Endpoint for receiving and processing SAML responses when Holder-of-key is used.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param samlResponse the base64-encoded SAML response
   * @param relayState the relay state
   * @return a model and view
   * @throws ApplicationException for application errors
   */
  @PostMapping("/hok")
  public @NonNull ModelAndView processHokResponse(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      @RequestParam("SAMLResponse") final @NonNull String samlResponse,
      @RequestParam(value = "RelayState", required = false) final @Nullable String relayState)
      throws ApplicationException {

    if (!this.hokActive) {
      throw new ApplicationException("sp.msg.error.no-hok");
    }
    return this.processResponse(request, response, false, true, samlResponse, relayState);
  }

  /**
   * Endpoint for receiving and processing SAML responses for "sign requests".
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param samlResponse the base64-encoded SAML response
   * @param relayState the relay state
   * @return a model and view
   * @throws ApplicationException for application errors
   */
  @PostMapping("/sign")
  public @NonNull ModelAndView processSignResponse(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      @RequestParam("SAMLResponse") final @NonNull String samlResponse,
      @RequestParam(value = "RelayState", required = false) final @Nullable String relayState)
      throws ApplicationException {

    return this.processResponse(request, response, true, false, samlResponse, relayState);
  }

  /**
   * Endpoint for receiving and processing SAML responses for "sign requests" when Holder-of-key is used.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param samlResponse the base64-encoded SAML response
   * @param relayState the relay state
   * @return a model and view
   * @throws ApplicationException for application errors
   */
  @PostMapping("/signhok")
  public @NonNull ModelAndView processHokSignResponse(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      @RequestParam("SAMLResponse") final @NonNull String samlResponse,
      @RequestParam(value = "RelayState", required = false) final @Nullable String relayState)
      throws ApplicationException {

    if (!this.hokActive) {
      throw new ApplicationException("sp.msg.error.no-hok");
    }

    return this.processResponse(request, response, true, true, samlResponse, relayState);
  }

  /**
   * Support method for processing responses.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param signFlag indicates whether this is a response for a "sign" AuthnRequest or a plain one
   * @param hokFlag indicates whether the response was received on a holder-of-key endpoint
   * @param samlResponse the base64-encoded SAML response
   * @param relayState the relay state
   * @return a model and view
   * @throws ApplicationException for application errors
   */
  private ModelAndView processResponse(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      final boolean signFlag, final boolean hokFlag,
      final String samlResponse, final String relayState) throws ApplicationException {

    log.debug("Received SAML response [client-ip-address='{}']", request.getRemoteAddr());

    final HttpSession session = request.getSession();

    final AuthnRequest authnRequest = (AuthnRequest) session.getAttribute("sp-request");
    if (authnRequest == null) {
      log.warn("No session for user [client-ip-address='{}']", request.getRemoteAddr());
      throw new ApplicationException("sp.msg.error.no-session", "AuthnRequest not found in session");
    }
    Boolean ping = (Boolean) session.getAttribute("ping");
    if (ping == null) {
      ping = false;
    }
    else {
      session.removeAttribute("ping");
    }
    final LastAuthentication previousAuthentication = (LastAuthentication) session.getAttribute("last-authentication");
    session.removeAttribute("last-authentication");

    // If this was a sign request, we get the sign message for display in the viww.
    final String signMessage = signFlag ? (String) session.getAttribute("sign-message") : null;
    session.removeAttribute("sign-message");

    final ModelAndView mav = new ModelAndView();

    final X509Certificate clientCertificate =
        hokFlag ? this.clientCertificateGetter.getClientCertificate(request) : null;
    if (hokFlag) {
      if (clientCertificate == null) {
        log.info("No client certificate received");
      }
      else {
        log.debug("Received client certificate: {}", clientCertificate);
      }
    }

    try {
      final ValidationContext validationContext = this.buildValidationContext(signMessage != null);
      final ResponseProcessingResult result = this.responseProcessor.processSamlResponse(
          samlResponse, relayState, new ResponseProcessingInputImpl(request, authnRequest, clientCertificate),
          validationContext);
      log.debug("Successfully processed SAML response");

      if (signFlag && previousAuthentication != null) {
        // If this was an authentication for signature operation we verify that the same user
        // performed the "signature" and the one that authenticated the first time.
        if (!previousAuthentication.isIdentityMatch(result.getAttributes())) {
          throw new ResponseProcessingException("You did not use the same eID for signature as for authentication.");
        }
      }

      if (signFlag) {
        mav.setViewName("success-sign");
        mav.addObject("signMessage", signMessage);
      }
      else {
        mav.setViewName("success");

        if (!ping) {
          mav.addObject("path-sign", "/saml2/request/next");
          final LastAuthentication lastAuthn = new LastAuthentication(result);
          lastAuthn.setHokUsed(hokFlag);
          session.setAttribute("last-authentication", lastAuthn);
        }
      }
      mav.addObject("authenticationInfo", this.createAuthenticationInfo(result));
      mav.addObject("ping", ping);
    }
    catch (final ResponseStatusErrorException e) {
      log.info("Received non successful status: {}", e.getMessage());
      final Status status = e.getStatus();
      final ErrorStatusInfo errorInfo = new ErrorStatusInfo(status);
      if (errorInfo.isCancel()) {
        return new ModelAndView("redirect:" + this.buildRedirectUrl("/", this.debugFlag));
      }
      else {
        mav.setViewName("saml-error");
        mav.addObject("status", errorInfo);
      }
    }
    catch (final ResponseProcessingException e) {
      log.warn("Error while processing SAML response - {}", e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.response-processing", e);
    }

    session.setAttribute("sp-result", mav);
    // return new ModelAndView("redirect:../result");
    return new ModelAndView("redirect:" + this.buildRedirectUrl("/result", this.debugFlag));
  }

  private String buildRedirectUrl(final String path, final boolean debug) {
    return String.format("%s%s%s",
        (debug ? this.debugBaseUri : this.baseUri), this.contextPath.equals("/") ? "" : this.contextPath, path);
  }

  private ValidationContext buildValidationContext(final boolean signSp) {
    final Map<String, Object> pars = new HashMap<>();
    pars.put(CoreValidatorParameters.SP_METADATA, signSp ? this.signSpMetadata : this.spMetadata);
    return new ValidationContext(pars);
  }

  /**
   * Creates an authentication info model object based on the response result.
   *
   * @param result the result from the response processing
   * @return the model
   */
  private AuthenticationInfo createAuthenticationInfo(final ResponseProcessingResult result) {
    final AuthenticationInfo authenticationInfo = new AuthenticationInfo();

    final String loa = result.getAuthnContextClassUri();
    final boolean isEidas = LoaMessages.apply(authenticationInfo, loa);

    final List<Attribute> unknownAttributes = new ArrayList<>();
    for (final Attribute a : result.getAttributes()) {
      final AttributeInfo ai = this.attributeInfoRegistry.resolve(a, isEidas);
      if (ai != null) {
        if (!ai.isAdvanced()) {
          authenticationInfo.getAttributes().add(ai);
        }
        else {
          authenticationInfo.getAdvancedAttributes().add(ai);
        }
      }
      else {
        unknownAttributes.add(a);
      }
    }

    authenticationInfo.setAttributes(authenticationInfo.getAttributes()
        .stream()
        .sorted(Comparator.comparing(AttributeInfo::getSortOrder))
        .collect(Collectors.toList()));

    authenticationInfo.setAdvancedAttributes(authenticationInfo.getAdvancedAttributes()
        .stream()
        .sorted(Comparator.comparing(AttributeInfo::getSortOrder))
        .collect(Collectors.toList()));

    return authenticationInfo;
  }

  private static class ResponseProcessingInputImpl implements ResponseProcessingInput {

    private final HttpServletRequest httpRequest;
    private final AuthnRequest authnRequest;
    private final X509Certificate clientCertificate;

    public ResponseProcessingInputImpl(final @NonNull HttpServletRequest httpRequest,
        final @NonNull AuthnRequest authnRequest, final @Nullable X509Certificate clientCertificate) {
      this.httpRequest = httpRequest;
      this.authnRequest = authnRequest;
      this.clientCertificate = clientCertificate;
    }

    @Override
    public @NonNull AuthnRequest getAuthnRequest(final @NonNull String id) {
      return this.authnRequest;
    }

    @Override
    public @Nullable String getRequestRelayState(final @NonNull String id) {
      return null;
    }

    @Override
    public @NonNull String getReceiveURL() {
      return this.httpRequest.getRequestURL().toString();
    }

    @Override
    public @NonNull Instant getReceiveInstant() {
      return Instant.now();
    }

    @Override
    public @NonNull String getClientIpAddress() {
      return this.httpRequest.getRemoteAddr();
    }

    @Override
    public @Nullable X509Certificate getClientCertificate() {
      return this.clientCertificate;
    }

  }

  /**
   * Assigns the user message templates.
   *
   * @param userMessages the user message templates
   */
  public void setUserMessages(final @NonNull Map<String, String> userMessages) {
    this.userMessages = userMessages;
  }

  /**
   * Assigns the context path.
   *
   * @param contextPath the context path
   */
  public void setContextPath(final @NonNull String contextPath) {
    this.contextPath = contextPath;
  }

  /**
   * Assigns the base uri.
   *
   * @param baseUri the base uri
   */
  public void setBaseUri(final @NonNull String baseUri) {
    this.baseUri = baseUri;
  }

  /**
   * Assigns the debug base uri.
   *
   * @param debugBaseUri the debug base uri
   */
  public void setDebugBaseUri(final @Nullable String debugBaseUri) {
    this.debugBaseUri = debugBaseUri;
  }

}
