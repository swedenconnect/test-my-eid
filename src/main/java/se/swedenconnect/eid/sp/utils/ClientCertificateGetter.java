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
package se.swedenconnect.eid.sp.utils;

import java.security.cert.X509Certificate;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Functional interface for getting the client TLS certificate (for HoK).
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@FunctionalInterface
public interface ClientCertificateGetter {

  /**
   * Gets the client TLS certificate.
   *
   * @param request the HTTP servlet request
   * @return the certificate, or null if none is found
   */
  X509Certificate getClientCertificate(final HttpServletRequest request);

}
