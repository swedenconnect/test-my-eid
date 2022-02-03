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

import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mobile.device.Device;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.google.common.base.Objects;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.eid.sp.config.IdpListConfiguration;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation.IdpModel;
import se.swedenconnect.eid.sp.model.LastAuthentication;

/**
 * Main controller.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Controller
@Slf4j
@RequestMapping("/")
public class SpController extends BaseController {

  /** Holds the IdPs to display for the user. */
  @Autowired
  private IdpListConfiguration idpListConfiguration;

  /** The entityID for the eIDAS connector. */
  @Value("${sp.eidas-connector.entity-id}")
  private String eidasConnectorEntityId;

  /** Needed so that we can configure paths. For overloading this app. */
  @Value("${sp.sign-path:/saml2/request/next}")
  protected String signPath;

  /**
   * Controller method for the home endpoint.
   *
   * @param device
   *          the type of device
   * @param debug
   *          debug flag
   *
   * @return a model and view object
   */
  @GetMapping
  public ModelAndView home(final HttpServletRequest request, final Device device,
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug) {
    final ModelAndView mav = new ModelAndView("home");
    mav.addObject("debug", debug);
    mav.addObject("idpList", this.idpListConfiguration.getIdps()
      .stream()
      .filter(idp -> device.isNormal() || idp.isMobileUse())
      .map(i -> i.getIdpModel(LocaleContextHolder.getLocale()))
      .collect(Collectors.toList()));
    
    log.trace("Adding IdPs {}", this.idpListConfiguration.getIdps());
    return mav;
  }

  /**
   * Controller that by-passes the discovery page and goes directly to the eIDAS connector.
   *
   * @param debug
   *          debug flag
   * @return a redirect string to the SAML request endpoint
   */
  @GetMapping("/eidas")
  public ModelAndView eidas(
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug) {

    return new ModelAndView(String.format("redirect:/saml2/request?selectedIdp=%s&debug=%s", this.eidasConnectorEntityId, debug));
  }

  /**
   * Controller that by-passes the discovery page and goes directly to the eIDAS connector with a pre-selected country.
   *
   * @param country
   *          the two-letter country code for the country to send the request from the connector to
   * @param debug
   *          debug flag
   * @return a redirect string to the SAML request endpoint
   */
  @GetMapping("/eidas/{country}")
  public ModelAndView eidasCountry(
      @PathVariable(value = "country", required = true) final String country,
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug) {

    if ("ping".equalsIgnoreCase(country)) {
      return new ModelAndView(String.format("redirect:/saml2/request?selectedIdp=%s&ping=true&debug=%s",
        this.eidasConnectorEntityId, debug));
    }
    else {
      return new ModelAndView(String.format("redirect:/saml2/request?selectedIdp=%s&country=%s&debug=%s",
        this.eidasConnectorEntityId, country, debug));
    }
  }

  /**
   * Controller that by-passes the discovery page and goes directly to the eIDAS connector with a pre-selected country
   * and sends an authentication request for an eIDAS ping authentication request.
   *
   * @param country
   *          the two-letter country code for the country to send the request from the connector to
   * @param debug
   *          debug flag
   * @return a redirect string to the SAML request endpoint
   */
  @GetMapping("/eidas/ping/{country}")
  public ModelAndView eidasPingCountry(
      @PathVariable(value = "country", required = true) final String country,
      @RequestParam(value = "debug", required = false, defaultValue = "false") final Boolean debug) {

    return new ModelAndView(String.format("redirect:/saml2/request?selectedIdp=%s&ping=true&country=%s&debug=%s",
      this.eidasConnectorEntityId, country, debug));
  }

  /**
   * Displays the result of an authentication.
   *
   * @param request
   *          the HTTP request
   * @param response
   *          the HTTP response
   * @return a model and view object
   * @throws ApplicationException
   *           for
   */
  @GetMapping("/result")
  public ModelAndView displayResult(final HttpServletRequest request, final HttpServletResponse response) {

    final HttpSession session = request.getSession();
    final ModelAndView mav = (ModelAndView) session.getAttribute("sp-result");
    if (mav == null) {
      log.warn("No session for user, directing to start page [client-ip-address='{}']", request.getRemoteAddr());
      return new ModelAndView("redirect:/");
    }

    final LastAuthentication lastAuthentication = (LastAuthentication) session.getAttribute("last-authentication");
    if (lastAuthentication != null) {
      final IdpModel idpModel = this.idpListConfiguration.getIdps().stream()
        .filter(idp -> Objects.equal(idp.getEntityID(), lastAuthentication.getIdp()))
        .map(idp -> idp.getIdpModel(LocaleContextHolder.getLocale()))
        .findFirst()
        .orElse(null);
      if (idpModel != null) {
        mav.addObject("signIdp", idpModel);
      }
    }
    mav.addObject("pathSign", this.signPath);

    return mav;
  }

}
