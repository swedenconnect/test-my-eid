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

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.extern.slf4j.Slf4j;

/**
 * Application error controller.
 * 
 * @author Martin Lindström (martin.lindstrom@idsec.se)
 */
@Controller
@ControllerAdvice
@Slf4j
public class ApplicationErrorController extends AbstractErrorController {

  /**
   * Constructor.
   */
  public ApplicationErrorController() {
    super(new DefaultErrorAttributes());
  }

  /**
   * Error handler.
   * 
   * @param request
   *          the HTTP request
   * @return a model and view object
   */
  @RequestMapping("/error")
  public ModelAndView handleError(HttpServletRequest request) {

    Map<String, Object> errorAttributes = this.getErrorAttributes(request, ErrorAttributeOptions.defaults());    
    
    if (log.isInfoEnabled()) {
      StringBuffer sb = new StringBuffer();
      for (Map.Entry<String, Object> e : errorAttributes.entrySet()) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(e.getKey()).append("=").append(e.getValue());
      }
      log.info("Error: {}", sb.toString());
    }

    ModelAndView mav = new ModelAndView("error");
    
    ApplicationException exception = this.getException(request, ApplicationException.class);
    if (exception != null) {
      log.info("Reporting error: msg-code='{}',message='{}'", exception.getMessageCode(), exception.getMessage());
      mav.addObject("messageCode", exception.getMessageCode());
      mav.addObject("message", exception.getMessage());
    }
    else {
      HttpStatus status = this.getStatus(request);

      if (HttpStatus.NOT_FOUND.equals(status)) {
        mav.addObject("messageCode", "sp.msg.error.not-found");
      }
      else {
        mav.addObject("messageCode", "sp.msg.error.internal");
      }
    }    
    
    request.getSession().setAttribute("sp-result", mav);    
    return new ModelAndView("redirect:/result");
  }

  /**
   * Returns the exception from the error attributes.
   * 
   * @param request
   *          the HTTP request
   * @param exceptionClass
   *          the exception class we are looking for
   * @return the exception or {@code null}
   */
  protected <T extends Exception> T getException(HttpServletRequest request, Class<T> exceptionClass) {
    Exception e = (Exception) request.getAttribute("javax.servlet.error.exception");
    while (e != null) {
      if (exceptionClass.isInstance(e)) {
        return exceptionClass.cast(e);
      }
      e = (Exception) e.getCause();
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public String getErrorPath() {
    return "/error";
  }

}
