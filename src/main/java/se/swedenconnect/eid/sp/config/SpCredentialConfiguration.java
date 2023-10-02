/*
 * Copyright 2018-2023 Sweden Connect
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
package se.swedenconnect.eid.sp.config;

import org.opensaml.security.x509.X509Credential;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.io.Resource;

import lombok.Setter;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/**
 * Configuration class for credentials.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Configuration
@ConfigurationProperties(prefix = "sp.credential")
@DependsOn("openSAML")
public class SpCredentialConfiguration {

  /** The signing credentials. */
  @Setter
  private CredentialsWrapper sign;

  /** The decryption credentials. */
  @Setter
  private CredentialsWrapper decrypt;

  /** The metadata signing credentials. */
  @Setter
  private CredentialsWrapper mdSign;

  @Bean("signCredential")
  public X509Credential signCredential() throws Exception {
    return this.sign != null ? new OpenSamlCredential(this.sign.getCredential()) : null;
  }

  @Bean("encryptCredential")
  public X509Credential encryptCredential() throws Exception {
    return this.decrypt != null ? new OpenSamlCredential(this.decrypt.getCredential()) : null;
  }

  @Bean("mdSignCredential")
  public X509Credential mdSignCredential() throws Exception {
    return this.mdSign != null ? new OpenSamlCredential(this.mdSign.getCredential()) : null;
  }

  /**
   * A wrapper to a {@link KeyStoreCredential}.
   */
  public static class CredentialsWrapper extends PkiCredentialConfigurationProperties {

    public void setFile(final Resource resource) {
      this.setResource(resource);
    }

    private PkiCredentialFactoryBean factory;

    public PkiCredential getCredential() throws Exception {
      if (this.factory == null) {
        this.factory = new PkiCredentialFactoryBean(this);
        this.factory.afterPropertiesSet();
      }
      return this.factory.getObject();
    }

  }

}
