/*
 * Copyright 2018-2024 Sweden Connect
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

import jakarta.servlet.http.HttpServletRequest;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.Map;

/**
 * Application error controller.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Controller
@ControllerAdvice
@Slf4j
public class ApplicationErrorController extends AbstractErrorController {

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
   * Constructor.
   */
  public ApplicationErrorController() {
    super(new DefaultErrorAttributes());
  }

  /**
   * Error handler.
   *
   * @param request the HTTP request
   * @return a model and view object
   */
  @RequestMapping("/error")
  public ModelAndView handleError(final HttpServletRequest request) {

    final Map<String, Object> errorAttributes = this.getErrorAttributes(request, ErrorAttributeOptions.defaults());

    if (log.isInfoEnabled()) {
      final StringBuilder sb = new StringBuilder();
      for (final Map.Entry<String, Object> e : errorAttributes.entrySet()) {
        if (!sb.isEmpty()) {
          sb.append(",");
        }
        sb.append(e.getKey()).append("=").append(e.getValue());
      }
      log.info("Error: {}", sb);
    }

    final ModelAndView mav = new ModelAndView("error");

    final ApplicationException exception = this.getException(request, ApplicationException.class);
    if (exception != null) {
      log.info("Reporting error: msg-code='{}',message='{}'", exception.getMessageCode(), exception.getMessage());
      mav.addObject("messageCode", exception.getMessageCode());
      mav.addObject("message", exception.getMessage());
    }
    else {
      final HttpStatus status = this.getStatus(request);

      if (HttpStatus.NOT_FOUND == status) {
        mav.addObject("messageCode", "sp.msg.error.not-found");
      }
      else {
        mav.addObject("messageCode", "sp.msg.error.internal");
      }
    }

    request.getSession().setAttribute("sp-result", mav);

    final String url = String.format("%s%s/result",
        StringUtils.hasText(this.debugBaseUri) ? this.debugBaseUri : this.baseUri,
        this.contextPath.equals("/") ? "" : this.contextPath);

    return new ModelAndView("redirect:" + url);
  }

  /**
   * Returns the exception from the error attributes.
   *
   * @param request the HTTP request
   * @param exceptionClass the exception class we are looking for
   * @return the exception or {@code null}
   */
  protected <T extends Exception> T getException(final HttpServletRequest request, final Class<T> exceptionClass) {
    Exception e = (Exception) request.getAttribute("javax.servlet.error.exception");
    while (e != null) {
      if (exceptionClass.isInstance(e)) {
        return exceptionClass.cast(e);
      }
      e = (Exception) e.getCause();
    }
    return null;
  }

}
