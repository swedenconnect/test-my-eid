/*
 * Copyright 2018-2022 Sweden Connect
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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
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

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.eid.sp.config.EntityID;
import se.swedenconnect.eid.sp.model.AttributeInfo;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.model.AuthenticationInfo;
import se.swedenconnect.eid.sp.model.ErrorStatusInfo;
import se.swedenconnect.eid.sp.model.LastAuthentication;
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
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;

/**
 * Controller for creating SAML {@code AuthnRequest} messages and for processing SAML responses.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Controller
@RequestMapping("/saml2")
@Slf4j
public class SamlController extends BaseController {

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
  
  @Setter
  @Value("${server.servlet.context-path}") 
  private String contextPath;
  
  @Setter
  @Value("${sp.base-uri}")
  private String baseUri;
  
  @Setter
  @Value("${sp.debug-base-uri:}")
  private String debugBaseUri;

  /**
   * Builds an {@code AuthnRequest}.
   *
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param selectedIdp
   *          the selected IdP
   * @param country
   *          optional parameter for direct requests to an eIDAS country
   * @param debug
   *          the debug flag
   * @return a model and view object
   * @throws ApplicationException
   *           for errors
   */
  @RequestMapping("/request")
  public ModelAndView sendRequest(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("selectedIdp") final String selectedIdp,
      @RequestParam(value = "country", required = false) final String country,
      @RequestParam(value = "ping", required = false, defaultValue = "false") final Boolean ping,
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug,
      @RequestParam(value = "useHok", required = false) final Boolean useHok) throws ApplicationException {

    log.debug("Request for generating an AuthnRequest to '{}' [client-ip-address='{}', debug='{}', country='{}']",
      selectedIdp, request.getRemoteAddr(), debug, country);
    
    // Special handling for LoA 4 and Holder-of-key
    //
    HokRequirement hokRequirement = HokRequirement.DONT_USE;
    if (useHok == null && this.hokActive && (country == null || ping)) {
      final HokSupport hokSupport = this.spAuthnRequestGenerator.getIdpHokSupport(selectedIdp);
      if (HokSupport.BOTH.equals(hokSupport)) {
        // Ask whether to use HoK or not ...
        final ModelAndView mav = new ModelAndView("ask-hok");
        mav.addObject("selectedIdp", selectedIdp);
        mav.addObject("debug", debug);
        return mav;
      }
      else if (HokSupport.ONLY_HOK.equals(hokSupport)) {
        hokRequirement = HokRequirement.REQUIRED;
      }
    }
    else if (useHok != null) {
      hokRequirement = useHok ? HokRequirement.REQUIRED : HokRequirement.DONT_USE;
    }

    try {
      final HttpSession session = request.getSession();

      final TestMyEidAuthnRequestGeneratorContext input = new TestMyEidAuthnRequestGeneratorContext(hokRequirement);       
      input.setDebug(debug);
      input.setCountry(country);
      input.setPing(ping);

      final RequestHttpObject<AuthnRequest> authnRequest = 
          this.spAuthnRequestGenerator.generateAuthnRequest(selectedIdp, null, input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.setAttribute("sp-debug", debug);
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
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param debug
   *          the debug flag
   * @return a model and view object
   * @throws ApplicationException
   *           for errors (session errors)
   */
  @RequestMapping("/request/next")
  public ModelAndView sendNextRequest(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug) throws ApplicationException {

    final HttpSession session = request.getSession();
    final LastAuthentication lastAuthentication = (LastAuthentication) session.getAttribute("last-authentication");
    if (lastAuthentication == null) {
      log.error("There is no session information available about the last authentication - cannot sign");
      throw new ApplicationException("sp.msg.error.no-session");
    }
    return this.sendSignRequest(request, response, lastAuthentication.getIdp(),
      lastAuthentication.getPersonalIdentityNumber(), lastAuthentication.getPrid(), lastAuthentication.getGivenName(),
      lastAuthentication.getAuthnContextUri(), debug, lastAuthentication.isHokUsed());
  }

  /**
   * Controller method for sending a request to force signature behaviour at the IdP.
   *
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param idp
   *          the IdP entityID
   * @param personalIdentityNumber
   *          the personal identity number (optional)
   * @param givenName
   *          the user given name (optional)
   * @param loa
   *          the level of assurance (sig-message URI), optional
   * @param debug
   *          the debug flag
   * @return a model and view object
   * @throws ApplicationException
   *           for errors
   */
  @RequestMapping("/request/sign")
  public ModelAndView sendSignRequest(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("idp") final String idp,
      @RequestParam(value = "pnr", required = false) final String personalIdentityNumber,
      @RequestParam(value = "prid", required = false) final String prid,
      @RequestParam(value = "givenName", required = false) final String givenName,
      @RequestParam(value = "loa", required = false) final String loa,
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug,
      @RequestParam(value = "hok", required = false, defaultValue = "false") final Boolean hokUsed) throws ApplicationException {

    log.debug(
      "Request for generating an AuthnRequest for a signature authentication to '{}' [client-ip-address='{}', personal-number='{}', debug='{}']",
      idp, request.getRemoteAddr(), personalIdentityNumber, debug);

    try {
      final HttpSession session = request.getSession();

      final TestMyEidAuthnRequestGeneratorContext input = new TestMyEidAuthnRequestGeneratorContext(
        hokUsed ? HokRequirement.REQUIRED : HokRequirement.DONT_USE);
      input.setDebug(debug);
      input.setPersonalIdentityNumberHint(personalIdentityNumber);
      input.setPridHint(prid);
      input.setRequestedAuthnContextUris(Arrays.asList(loa));

      // Load signature message ...
      //
      final String signMessage = givenName != null
          ? this.messageSource.getMessage("sp.msg.sign-message", new Object[] { givenName }, LocaleContextHolder.getLocale())
          : this.messageSource.getMessage("sp.msg.sigm-message-noname", null, LocaleContextHolder.getLocale());

      input.setSignMessage(signMessage);
      session.setAttribute("sign-message", signMessage);

      final RequestHttpObject<AuthnRequest> authnRequest = 
          this.signSpAuthnRequestGenerator.generateAuthnRequest(idp, null, input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.removeAttribute("sp-result");
      session.setAttribute("sp-debug", debug);

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
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param samlResponse
   *          the base64-encoded SAML response
   * @param relayState
   *          the relay state
   * @return a model and view
   * @throws ApplicationException
   *           for application errors
   */
  @PostMapping("/post")
  public ModelAndView processResponse(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("SAMLResponse") final String samlResponse,
      @RequestParam(value = "RelayState", required = false) final String relayState) throws ApplicationException {

    return this.processResponse(request, response, false, false, samlResponse, relayState);
  }

  @PostMapping("/hok")
  public ModelAndView processHokResponse(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("SAMLResponse") final String samlResponse,
      @RequestParam(value = "RelayState", required = false) final String relayState) throws ApplicationException {

    if (!hokActive) {
      throw new ApplicationException("sp.msg.error.no-hok");
    }
    return this.processResponse(request, response, false, true, samlResponse, relayState);
  }

  /**
   * Endpoint for receiving and processing SAML responses for "sign requests".
   *
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param samlResponse
   *          the base64-encoded SAML response
   * @param relayState
   *          the relay state
   * @return a model and view
   * @throws ApplicationException
   *           for application errors
   */
  @PostMapping("/sign")
  public ModelAndView processSignResponse(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("SAMLResponse") final String samlResponse,
      @RequestParam(value = "RelayState", required = false) final String relayState) throws ApplicationException {

    return this.processResponse(request, response, true, false, samlResponse, relayState);
  }

  @PostMapping("/signhok")
  public ModelAndView processHokSignResponse(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam("SAMLResponse") final String samlResponse,
      @RequestParam(value = "RelayState", required = false) final String relayState) throws ApplicationException {

    if (!hokActive) {
      throw new ApplicationException("sp.msg.error.no-hok");
    }

    return this.processResponse(request, response, true, true, samlResponse, relayState);
  }

  /**
   * Support method for processing responses.
   *
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param signFlag
   *          indicates whether this is a response for a "sign" AuthnRequest or a plain one
   * @param hokFlag
   *          indicates whether the response was received on a holder-of-key endpoint
   * @param samlResponse
   *          the base64-encoded SAML response
   * @param relayState
   *          the relay state
   * @return a model and view
   * @throws ApplicationException
   *           for application errors
   */
  private ModelAndView processResponse(final HttpServletRequest request, final HttpServletResponse response, 
      final boolean signFlag, final boolean hokFlag,
      final String samlResponse, final String relayState) throws ApplicationException {

    log.debug("Received SAML response [client-ip-address='{}']", request.getRemoteAddr());

    final HttpSession session = request.getSession();
    
    final boolean debug = Optional.ofNullable(session.getAttribute("sp-debug"))
        .map(Boolean.class::cast)
        .orElse(false);        
    
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
    
    final X509Certificate clientCertificate = hokFlag ? this.clientCertificateGetter.getClientCertificate(request) : null;
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
        samlResponse, relayState, new ResponseProcessingInputImpl(request, authnRequest, clientCertificate), validationContext);
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
      mav.addObject("debug", debug);
    }
    catch (final ResponseStatusErrorException e) {
      log.info("Received non successful status: {}", e.getMessage());
      final Status status = e.getStatus();
      final ErrorStatusInfo errorInfo = new ErrorStatusInfo(status);
      if (errorInfo.isCancel()) {
        //return new ModelAndView("redirect:../");
        return new ModelAndView("redirect:" + this.buildRedirectUrl("/", debug));
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
    //return new ModelAndView("redirect:../result");
    return new ModelAndView("redirect:" + this.buildRedirectUrl("/result", debug));
  }
  
  private String buildRedirectUrl(final String path, final boolean debug) {
      return String.format("%s%s%s", 
        (debug ? this.debugBaseUri : this.baseUri), contextPath.equals("/") ? "" : this.contextPath, path);
  }
  
  private ValidationContext buildValidationContext(final boolean signSp) {
    Map<String, Object> pars = new HashMap<>();
    pars.put(CoreValidatorParameters.SP_METADATA, signSp ? this.signSpMetadata : this.spMetadata);
    final ValidationContext ctx = new ValidationContext(pars);    
    return ctx;
  }

  /**
   * Creates an authentication info model object based on the response result.
   *
   * @param result
   *          the result from the response processing
   * @return the model
   */
  private AuthenticationInfo createAuthenticationInfo(final ResponseProcessingResult result) {
    final AuthenticationInfo authenticationInfo = new AuthenticationInfo();

    final String loa = result.getAuthnContextClassUri();
    boolean isEidas = false;

    authenticationInfo.setLoaUri(loa);

    if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3.equals(loa) ||
        "http://id.swedenconnect.se/loa/1.0/uncertified-loa3-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3-uncertified");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3_NONRESIDENT.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3-nonresident");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2-uncertified");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2_NONRESIDENT.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2-nonresident");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa4-sigmessage".equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa4");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4_NONRESIDENT.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa4-nonresident");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-low-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_LOW.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-low");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      authenticationInfo.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-sub-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_SUBSTANTIAL.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-substantial");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      authenticationInfo.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-high-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_HIGH.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-high");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      authenticationInfo.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)) {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        authenticationInfo.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (TestMyEidAuthnRequestGeneratorContext.EIDAS_PING_LOA.equals(loa)) {
      authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-eidas-test");
      authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-eidas-test.desc");
      isEidas = true;
    }
    else {
      log.error("Uknown LoA: {}", loa);
    }

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

    public ResponseProcessingInputImpl(final HttpServletRequest httpRequest, 
        final AuthnRequest authnRequest, final X509Certificate clientCertificate) {
      this.httpRequest = httpRequest;
      this.authnRequest = authnRequest;
      this.clientCertificate = clientCertificate;
    }

    @Override
    public AuthnRequest getAuthnRequest(final String id) {
      return this.authnRequest;
    }

    @Override
    public String getRequestRelayState(final String id) {
      return null;
    }

    @Override
    public String getReceiveURL() {
      return this.httpRequest.getRequestURL().toString();
    }

    @Override
    public Instant getReceiveInstant() {
      return Instant.now();
    }

    @Override
    public String getClientIpAddress() {
      return this.httpRequest.getRemoteAddr();
    }

    @Override
    public X509Certificate getClientCertificate() {
      return this.clientCertificate;
    }

  }

}
