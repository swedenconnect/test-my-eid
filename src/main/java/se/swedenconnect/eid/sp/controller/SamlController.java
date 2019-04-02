/*
 * Copyright 2018-2019 Sweden Connect
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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.litsec.opensaml.saml2.common.request.RequestGenerationException;
import se.litsec.opensaml.saml2.common.request.RequestHttpObject;
import se.litsec.opensaml.saml2.common.response.ResponseProcessingException;
import se.litsec.opensaml.saml2.common.response.ResponseProcessingInput;
import se.litsec.opensaml.saml2.common.response.ResponseProcessingResult;
import se.litsec.opensaml.saml2.common.response.ResponseProcessor;
import se.litsec.opensaml.saml2.common.response.ResponseStatusErrorException;
import se.litsec.opensaml.saml2.metadata.PeerMetadataResolver;
import se.litsec.opensaml.saml2.metadata.provider.MetadataProvider;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI;
import se.swedenconnect.eid.sp.config.EntityID;
import se.swedenconnect.eid.sp.model.AttributeInfo;
import se.swedenconnect.eid.sp.model.AttributeInfoRegistry;
import se.swedenconnect.eid.sp.model.AuthenticationInfo;
import se.swedenconnect.eid.sp.model.ErrorStatusInfo;
import se.swedenconnect.eid.sp.model.LastAuthentication;
import se.swedenconnect.eid.sp.saml.AuthnRequestGenerator;
import se.swedenconnect.eid.sp.saml.AuthnRequestGeneratorInput;

/**
 * Controller for creating SAML {@code AuthnRequest} messages and for processing SAML responses.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Controller
@RequestMapping("/saml2")
@Slf4j
public class SamlController extends BaseController {

  /** For generating a SAML AuthnRequest message. */
  @Autowired
  @Qualifier("spAuthnRequestGenerator")
  private AuthnRequestGenerator spAuthnRequestGenerator;

  /** For generating a SAML AuthnRequest message for the signature service. */
  @Autowired
  @Qualifier("signSpAuthnRequestGenerator")
  private AuthnRequestGenerator signSpAuthnRequestGenerator;

  /** For processing SAML responses. */
  @Autowired
  private ResponseProcessor responseProcessor;

  /** The SP entity ID. */
  @Autowired
  @Qualifier("spEntityID")
  private EntityID spEntityID;

  /** The entityID for the sign service SP. */
  @Autowired
  @Qualifier("signSpEntityID")
  private EntityID signSpEntityID;

  /** The federation metadata provider. */
  @Autowired
  private MetadataProvider metadataProvider;

  /** For displaying of SAML attributes. */
  @Autowired
  private AttributeInfoRegistry attributeInfoRegistry;

  /** Holds localized messages. */
  @Autowired
  private MessageSource messageSource;

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
  public ModelAndView sendRequest(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("selectedIdp") String selectedIdp,
      @RequestParam(value = "country", required = false) String country,
      @RequestParam(value = "debug", required = false, defaultValue = "false") Boolean debug) throws ApplicationException {

    log.debug("Request for generating an AuthnRequest to '{}' [client-ip-address='{}', debug='{}', country='{}']", selectedIdp, request
      .getRemoteAddr(),
      debug, country);

    try {
      HttpSession session = request.getSession();

      AuthnRequestGeneratorInput input = new AuthnRequestGeneratorInput(selectedIdp);
      input.setDebug(debug);
      input.setCountry(country);

      RequestHttpObject<AuthnRequest> authnRequest = this.spAuthnRequestGenerator.generateRequest(input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.setAttribute("sp-debug", debug);
      session.removeAttribute("sp-result");
      session.removeAttribute("last-authentication");

      if (SAMLConstants.POST_METHOD.equals(authnRequest.getMethod())) {
        ModelAndView mav = new ModelAndView("post-request");
        mav.addObject("action", authnRequest.getSendUrl());
        mav.addAllObjects(authnRequest.getRequestParameters());
        return mav;
      }
      else {
        return new ModelAndView("redirect:" + authnRequest.getSendUrl());
      }
    }
    catch (RequestGenerationException e) {
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
  public ModelAndView sendNextRequest(HttpServletRequest request, HttpServletResponse response,
      @RequestParam(value = "debug", required = false, defaultValue = "false") Boolean debug) throws ApplicationException {

    HttpSession session = request.getSession();
    LastAuthentication lastAuthentication = (LastAuthentication) session.getAttribute("last-authentication");
    if (lastAuthentication == null) {
      log.error("There is no session information available about the last authentication - cannot sign");
      throw new ApplicationException("sp.msg.error.no-session");
    }
    return this.sendSignRequest(request, response, lastAuthentication.getIdp(),
      lastAuthentication.getPersonalIdentityNumber(), lastAuthentication.getGivenName(),
      lastAuthentication.getSignMessageAuthnContextUri(), debug);
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
  public ModelAndView sendSignRequest(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("idp") String idp,
      @RequestParam(value = "pnr", required = false) String personalIdentityNumber,
      @RequestParam(value = "givenName", required = false) String givenName,
      @RequestParam(value = "loa", required = false) String loa,
      @RequestParam(value = "debug", required = false, defaultValue = "false") Boolean debug) throws ApplicationException {

    log.debug(
      "Request for generating an AuthnRequest for a signature authentication to '{}' [client-ip-address='{}', personal-number='{}', debug='{}']",
      idp, request.getRemoteAddr(), personalIdentityNumber, debug);

    try {
      HttpSession session = request.getSession();

      AuthnRequestGeneratorInput input = new AuthnRequestGeneratorInput(idp);
      input.setDebug(debug);
      input.setPersonalIdentityNumberHint(personalIdentityNumber);
      input.setRequestedAuthnContextUri(loa);

      // Load signature message ...
      //
      String signMessage = givenName != null
          ? this.messageSource.getMessage("sp.msg.sign-message", new Object[] { givenName }, LocaleContextHolder.getLocale())
          : this.messageSource.getMessage("sp.msg.sigm-message-noname", null, LocaleContextHolder.getLocale());

      input.setSignMessage(signMessage);
      session.setAttribute("sign-message", signMessage);

      RequestHttpObject<AuthnRequest> authnRequest = this.signSpAuthnRequestGenerator.generateRequest(input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.removeAttribute("sp-result");
      session.setAttribute("sp-debug", debug);

      if (SAMLConstants.POST_METHOD.equals(authnRequest.getMethod())) {
        ModelAndView mav = new ModelAndView("post-request");
        mav.addObject("action", authnRequest.getSendUrl());
        mav.addAllObjects(authnRequest.getRequestParameters());
        return mav;
      }
      else {
        return new ModelAndView("redirect:" + authnRequest.getSendUrl());
      }
    }
    catch (RequestGenerationException e) {
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
  public ModelAndView processResponse(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("SAMLResponse") String samlResponse,
      @RequestParam(value = "RelayState", required = false) String relayState) throws ApplicationException {

    return this.processResponse(request, response, false, samlResponse, relayState);
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
  public ModelAndView processSignResponse(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("SAMLResponse") String samlResponse,
      @RequestParam(value = "RelayState", required = false) String relayState) throws ApplicationException {

    return this.processResponse(request, response, true, samlResponse, relayState);
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
   * @param samlResponse
   *          the base64-encoded SAML response
   * @param relayState
   *          the relay state
   * @return a model and view
   * @throws ApplicationException
   *           for application errors
   */
  private ModelAndView processResponse(HttpServletRequest request, HttpServletResponse response, boolean signFlag,
      String samlResponse, String relayState) throws ApplicationException {

    log.debug("Received SAML response [client-ip-address='{}']", request.getRemoteAddr());

    HttpSession session = request.getSession();
    AuthnRequest authnRequest = (AuthnRequest) session.getAttribute("sp-request");
    if (authnRequest == null) {
      log.warn("No session for user [client-ip-address='{}']", request.getRemoteAddr());
      throw new ApplicationException("sp.msg.error.no-session");
    }
    final LastAuthentication previousAuthentication = (LastAuthentication) session.getAttribute("last-authentication"); 
    session.removeAttribute("last-authentication");

    // If this was a sign request, we get the sign message for display in the viww.
    String signMessage = signFlag ? (String) session.getAttribute("sign-message") : null;
    session.removeAttribute("sign-message");

    PeerMetadataResolver idpMetadataResolver = (entityID) -> {
      try {
        return metadataProvider.getEntityDescriptor(entityID).orElse(null);
      }
      catch (ResolverException e) {
        log.error("Error getting metadata for '{}'", entityID, e);
        return null;
      }
    };

    ModelAndView mav = new ModelAndView();

    try {
      ResponseProcessingResult result = this.responseProcessor.processSamlResponse(
        samlResponse, relayState, new ResponseProcessingInputImpl(request, authnRequest), idpMetadataResolver, null);
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
        session.setAttribute("last-authentication", new LastAuthentication(result));
      }
      mav.addObject("authenticationInfo", this.createAuthenticationInfo(result));

      Boolean debug = (Boolean) session.getAttribute("sp-debug");
      mav.addObject("debug", debug != null ? debug : Boolean.FALSE);
    }
    catch (ResponseStatusErrorException e) {
      log.info("Received non successful status: {}", e.getMessage());
      final Status status = e.getStatus();
      ErrorStatusInfo errorInfo = new ErrorStatusInfo(status);
      if (errorInfo.isCancel()) {
        return new ModelAndView("redirect:../");
      }
      else {
        mav.setViewName("saml-error");
        mav.addObject("status", errorInfo);
      }
    }
    catch (ResponseProcessingException e) {
      log.warn("Error while processing SAML response - {}", e.getMessage(), e);
      throw new ApplicationException("sp.msg.error.response-processing", e);
    }

    session.setAttribute("sp-result", mav);
    return new ModelAndView("redirect:../result");
  }

  /**
   * Creates an authentication info model object based on the response result.
   * 
   * @param result
   *          the result from the response processing
   * @return the model
   */
  private AuthenticationInfo createAuthenticationInfo(ResponseProcessingResult result) {
    AuthenticationInfo authenticationInfo = new AuthenticationInfo();

    final String loa = result.getAuthnContextClassUri();

    authenticationInfo.setLoaUri(loa);
    LevelofAssuranceAuthenticationContextURI.LoaEnum loaEnum = LevelofAssuranceAuthenticationContextURI.LoaEnum.parse(loa);
    if (loaEnum != null) {
      String baseUri = loaEnum.getBaseUri();      
      if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_LOA3.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
      }
      else if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_UNCERTIFIED_LOA3.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa3-uncertified");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
      }
      else if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_EIDAS_LOW.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-low");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
        authenticationInfo.setNotifiedInfoMessageCode(
          loaEnum.isNotified() ? "sp.msg.authn-according-notified" : "sp.msg.authn-according-non-notified");
        authenticationInfo.setEidasAssertion(true);
      }
      else if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-substantial");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
        authenticationInfo.setNotifiedInfoMessageCode(
          loaEnum.isNotified() ? "sp.msg.authn-according-notified" : "sp.msg.authn-according-non-notified");
        authenticationInfo.setEidasAssertion(true);
      }
      else if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_EIDAS_HIGH.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa-high");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
        authenticationInfo.setNotifiedInfoMessageCode(
          loaEnum.isNotified() ? "sp.msg.authn-according-notified" : "sp.msg.authn-according-non-notified");
        authenticationInfo.setEidasAssertion(true);
      }
      else if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_LOA2.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa2");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
      }
      else if (LevelofAssuranceAuthenticationContextURI.AUTH_CONTEXT_URI_LOA4.equals(baseUri)) {
        authenticationInfo.setLoaLevelMessageCode("sp.msg.authn-according-loa4");
        authenticationInfo.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
      }
      else {
        log.error("Uknown LoA: {}", loa);
      }
    }
    else {
      log.error("Uknown LoA: {}", loa);
    }

    final boolean isEidas = loaEnum.isEidasUri();

    List<Attribute> unknownAttributes = new ArrayList<>();

    for (Attribute a : result.getAttributes()) {
      AttributeInfo ai = this.attributeInfoRegistry.resolve(a, isEidas);
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

    private HttpServletRequest httpRequest;
    private AuthnRequest authnRequest;

    public ResponseProcessingInputImpl(HttpServletRequest httpRequest, AuthnRequest authnRequest) {
      this.httpRequest = httpRequest;
      this.authnRequest = authnRequest;
    }

    @Override
    public AuthnRequest getAuthnRequest() {
      return this.authnRequest;
    }

    @Override
    public String getRelayState() {
      return null;
    }

    @Override
    public String getReceiveURL() {
      return httpRequest.getRequestURL().toString();
    }

    @Override
    public long getReceiveInstant() {
      return System.currentTimeMillis();
    }

    @Override
    public String getClientIpAddress() {
      return httpRequest.getRemoteAddr();
    }

  }

}
