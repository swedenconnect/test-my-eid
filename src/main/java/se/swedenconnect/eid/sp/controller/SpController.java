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

import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mobile.device.Device;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.eid.sp.config.IdpListConfiguration;

/**
 * Main controller.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Controller
@Slf4j
@RequestMapping("/")
public class SpController extends BaseController {

  /** Holds the IdPs to display for the user. */
  @Autowired
  private IdpListConfiguration idpListConfiguration;

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
  public ModelAndView home(Device device, @RequestParam(value = "debug", required = false, defaultValue = "false") Boolean debug) {
    ModelAndView mav = new ModelAndView("home");
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
  public ModelAndView displayResult(HttpServletRequest request, HttpServletResponse response) {

    HttpSession session = request.getSession();
    ModelAndView mav = (ModelAndView) session.getAttribute("sp-result");
    if (mav == null) {
      log.warn("No session for user, directing to start page [client-ip-address='{}']", request.getRemoteAddr());
      return new ModelAndView("redirect:/");
    }

    return mav;
  }

}
