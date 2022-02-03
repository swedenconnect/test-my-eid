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
package se.swedenconnect.eid.sp;

import java.io.FileNotFoundException;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.Ssl.ClientAuth;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import lombok.Data;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Component
@Profile("local")
@Slf4j
public class DebugTomcatWebServerConfiguration implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

  @Autowired(required = false)
  @Setter
  private AdditionalConnectorSettings additionalConnectorSettings;

  @Override
  public void customize(final TomcatServletWebServerFactory factory) {
    if (this.additionalConnectorSettings != null && this.additionalConnectorSettings.getPort() != null) {
      try {
        factory.addAdditionalTomcatConnectors(this.createSslConnector());
      }
      catch (final FileNotFoundException e) {
        log.error("Failed to configure mTLS connector", e);
        throw new RuntimeException("Failed to configure mTLS connector", e);
      }
    }
  }

  private Connector createSslConnector() throws FileNotFoundException {
    final Connector connector = new Connector(Http11NioProtocol.class.getName());
    connector.setPort(this.additionalConnectorSettings.getPort());
    connector.setSecure(true);
    connector.setScheme("https");

    final Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
    if (this.additionalConnectorSettings.getSsl() == null || !this.additionalConnectorSettings.getSsl().isEnabled()) {
      protocol.setSSLEnabled(false);
    }
    else {
      protocol.setSSLEnabled(true);
      protocol.setKeystoreFile(ResourceUtils.getFile(this.additionalConnectorSettings.getSsl().getKeyStore()).getAbsolutePath());
      protocol.setKeyAlias(this.additionalConnectorSettings.getSsl().getKeyAlias());
      protocol.setKeystorePass(this.additionalConnectorSettings.getSsl().getKeyStorePassword());
      protocol.setKeyPass(this.additionalConnectorSettings.getSsl().getKeyPassword());      
      protocol.setSslProtocol("TLS");
      
      if (this.additionalConnectorSettings.getSsl().getClientAuth() != null
          && !ClientAuth.NONE.equals(this.additionalConnectorSettings.getSsl().getClientAuth())) {
        if (ClientAuth.NEED.equals(this.additionalConnectorSettings.getSsl().getClientAuth())) {
          protocol.setClientAuth("required");
        }
        else {
          protocol.setClientAuth("optional");          
        }
        protocol.setTruststoreFile(ResourceUtils.getFile(
          this.additionalConnectorSettings.getSsl().getTrustStore()).getAbsolutePath());
        protocol.setTruststorePass(this.additionalConnectorSettings.getSsl().getTrustStorePassword());
      }
    }
    return connector;
  }

  @Configuration
  @ConfigurationProperties("server2")
  @Data
  public static class AdditionalConnectorSettings {
    private Integer port;
    private Ssl ssl;
  }
}
