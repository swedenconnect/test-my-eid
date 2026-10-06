/*
 * Copyright 2018-2026 Sweden Connect
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
package se.swedenconnect.eid.sp.config.tomcat;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.Ssl.ClientAuth;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

/**
 * Adds an extra TLS connector (for mTLS) when running with the {@code local} profile.
 */
@Component
@Profile("local")
public class DebugTomcatWebServerConfiguration implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(DebugTomcatWebServerConfiguration.class);

  /** Settings for the additional connector. */
  @Autowired(required = false)
  private @Nullable AdditionalConnectorSettings additionalConnectorSettings;

  /**
   * Assigns the settings for the additional connector.
   *
   * @param additionalConnectorSettings the settings
   */
  public void setAdditionalConnectorSettings(final @Nullable AdditionalConnectorSettings additionalConnectorSettings) {
    this.additionalConnectorSettings = additionalConnectorSettings;
  }

  /** {@inheritDoc} */
  @Override
  public void customize(final @NonNull TomcatServletWebServerFactory factory) {
    if (this.additionalConnectorSettings != null && this.additionalConnectorSettings.getPort() != null) {
      try {
        factory.addAdditionalConnectors(this.createSslConnector());
      }
      catch (final Exception e) {
        log.error("Failed to configure mTLS connector", e);
        throw new RuntimeException("Failed to configure mTLS connector", e);
      }
    }
  }

  private Connector createSslConnector() throws Exception {
    final Connector connector = new Connector(Http11NioProtocol.class.getName());
    connector.setPort(this.additionalConnectorSettings.getPort());
    connector.setSecure(true);
    connector.setScheme("https");

    final Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
    if (this.additionalConnectorSettings.getSsl() == null || !this.additionalConnectorSettings.getSsl().isEnabled()) {
      protocol.setSSLEnabled(false);
    }
    else {
      final SSLHostConfig sslHostConfig = new SSLHostConfig();
      sslHostConfig.setSslProtocol("TLS");
      protocol.addSslHostConfig(sslHostConfig);
      protocol.setSSLEnabled(true);

      if (this.additionalConnectorSettings.getSsl().getKeyStore() != null) {
        final SSLHostConfigCertificate clientCert = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        clientCert.setCertificateKeystoreFile(
            ResourceUtils.getFile(this.additionalConnectorSettings.getSsl().getKeyStore()).getAbsolutePath());
        clientCert.setCertificateKeystorePassword(this.additionalConnectorSettings.getSsl().getKeyStorePassword());
        clientCert.setCertificateKeyAlias(this.additionalConnectorSettings.getSsl().getKeyAlias());
        clientCert.setCertificateKeyPassword(this.additionalConnectorSettings.getSsl().getKeyPassword());

        sslHostConfig.addCertificate(clientCert);
      }

      if (this.additionalConnectorSettings.getSsl().getClientAuth() != null
          && ClientAuth.NONE != this.additionalConnectorSettings.getSsl().getClientAuth()) {
        if (ClientAuth.NEED == this.additionalConnectorSettings.getSsl().getClientAuth()) {
          sslHostConfig.setCertificateVerification("required");
        }
        else {
          sslHostConfig.setCertificateVerification("optional");
        }
      }

      if (this.additionalConnectorSettings.getSsl().getTrustStore() != null) {
        sslHostConfig.setTruststoreFile(ResourceUtils.getFile(
            this.additionalConnectorSettings.getSsl().getTrustStore()).getAbsolutePath());
        sslHostConfig.setTruststorePassword(
            this.additionalConnectorSettings.getSsl().getTrustStorePassword());
      }
    }
    return connector;
  }

  /**
   * Configuration properties for the additional connector.
   */
  @Configuration
  @ConfigurationProperties("server2")
  public static class AdditionalConnectorSettings {

    /**
     * Server HTTP port.
     */
    private @Nullable Integer port;

    /**
     * SSL settings.
     */
    private @Nullable Ssl ssl;

    /**
     * Gets the server HTTP port.
     *
     * @return the port
     */
    public @Nullable Integer getPort() {
      return this.port;
    }

    /**
     * Assigns the server HTTP port.
     *
     * @param port the port
     */
    public void setPort(final @Nullable Integer port) {
      this.port = port;
    }

    /**
     * Gets the SSL settings.
     *
     * @return the SSL settings
     */
    public @Nullable Ssl getSsl() {
      return this.ssl;
    }

    /**
     * Assigns the SSL settings.
     *
     * @param ssl the SSL settings
     */
    public void setSsl(final @Nullable Ssl ssl) {
      this.ssl = ssl;
    }

    /** {@inheritDoc} */
    @Override
    public @NonNull String toString() {
      return "DebugTomcatWebServerConfiguration.AdditionalConnectorSettings(port=" + this.port + ", ssl=" + this.ssl
          + ")";
    }
  }

}
