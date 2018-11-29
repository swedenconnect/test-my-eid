/*
 * Copyright 2018 Sweden Connect
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
  private AuthnRequestGenerator authnRequestGenerator;

  /** For processing SAML responses. */
  @Autowired
  private ResponseProcessor responseProcessor;

  /** The SP entity ID. */
  @Autowired
  @Qualifier("spEntityID")
  private EntityID spEntityID;

  /** The federation metadata provider. */
  @Autowired
  private MetadataProvider metadataProvider;

  /** For displaying of SAML attributes. */
  @Autowired
  private AttributeInfoRegistry attributeInfoRegistry;

  /**
   * Builds an {@code AuthnRequest}.
   * 
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @param debug
   *          the debug flag
   * @return a model and view object
   * @throws ApplicationException
   *           for errors
   */
  @PostMapping("/request")
  public ModelAndView sendRequest(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("selectedIdp") String selectedIdp,
      @RequestParam(value = "debug", required = false, defaultValue = "false") Boolean debug) throws ApplicationException {

    log.debug("Request for generating an AuthnRequest to '{}' [client-ip-address='{}', debug='{}']", selectedIdp, request.getRemoteAddr(),
      debug);

    try {
      HttpSession session = request.getSession();

      AuthnRequestGeneratorInput input = new AuthnRequestGeneratorInput(selectedIdp);
      input.setDebug(debug);

      RequestHttpObject<AuthnRequest> authnRequest = this.authnRequestGenerator.generateRequest(input);

      // Save the request in the session so that we can use it when verifying the response.
      //
      session.setAttribute("sp-request", authnRequest.getRequest());
      session.removeAttribute("sp-result");

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

    log.debug("Received SAML response [client-ip-address='{}']", request.getRemoteAddr());

    HttpSession session = request.getSession();
    AuthnRequest authnRequest = (AuthnRequest) session.getAttribute("sp-request");
    if (authnRequest == null) {
      log.warn("No session for user [client-ip-address='{}']", request.getRemoteAddr());
      throw new ApplicationException("sp.msg.error.no-session");
    }

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

      mav.setViewName("success");
      mav.addObject("authenticationInfo", this.createAuthenticationInfo(result));
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
