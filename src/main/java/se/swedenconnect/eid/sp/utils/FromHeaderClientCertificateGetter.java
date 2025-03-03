/*
 * Copyright 2018-2025 Sweden Connect
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementation that gets the client certificate from a header.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Slf4j
public class FromHeaderClientCertificateGetter implements ClientCertificateGetter {

  /** Indicates that the certificate is in PEM-format. */
  private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";

  /** Factory for creating X.509 certificates. */
  private static final CertificateFactory factory;

  static {
    try {
      factory = CertificateFactory.getInstance("X.509");
    }
    catch (final CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  /** The name of the header that contains the client certificate. */
  private final String headerName;

  /**
   * Constructor.
   *
   * @param headerName the header name
   */
  public FromHeaderClientCertificateGetter(final String headerName) {
    this.headerName = headerName;
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getClientCertificate(final HttpServletRequest request) {
    final String header = request.getHeader(this.headerName);
    if (!StringUtils.hasText(header)) {
      return null;
    }

    try {
      if (!StringUtils.hasText(BEGIN_CERT)) {
        // OK, it's only a base64 encoding but not PEM
        try (final InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(header))) {
          return (X509Certificate) factory.generateCertificate(is);
        }
      }
      else {
        // PEM
        try (final InputStream is = new ByteArrayInputStream(header.getBytes(StandardCharsets.UTF_8))) {
          return (X509Certificate) factory.generateCertificate(is);
        }
      }
    }
    catch (final CertificateException | IOException e) {
      log.warn("Failed to read client certificate", e);
      return null;
    }
  }

}
