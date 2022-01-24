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
package se.swedenconnect.eid.sp.utils;

import java.security.cert.X509Certificate;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;

/**
 * Implementation for {@link ClientCertificateGetter} that gets the certificate from a request attribute.
 * 
 * @author Martin Lindström (martin@idsec.se)
 */
public class FromRequestAttributeClientCertificateGetter implements ClientCertificateGetter {
  
  private final String attributeName;
  
  /**
   * Constructor
   * 
   * @param attributeName the attribute name
   */
  public FromRequestAttributeClientCertificateGetter(final String attributeName) {
    this.attributeName = Objects.requireNonNull(attributeName, "attributeName must be set");
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getClientCertificate(final HttpServletRequest request) {
    // "javax.servlet.request.X509Certificate"
    final X509Certificate[] certs = (X509Certificate[]) request.getAttribute(attributeName);
    if (certs == null || certs.length == 0) {
      return null;
    }
    return certs[0];
  }

}
