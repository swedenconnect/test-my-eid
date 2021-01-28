/*
 * Copyright 2018-2021 Sweden Connect
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

import java.util.Optional;

import org.opensaml.security.x509.X509Credential;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.io.Resource;

import lombok.Setter;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
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
  public static class CredentialsWrapper {
    
    /** The resource holding the keystore file. */
    @Setter
    private Resource file;
    
    /** The type of keystore. */
    @Setter
    private String type;
    
    /** The keystore password. */
    @Setter
    private String password;
    
    /** The alias. */
    @Setter
    private String alias;
    
    /** The key password. */
    @Setter
    private String keyPassword;

    /** The credential. */
    private PkiCredential credential;
    
    public PkiCredential getCredential() throws Exception {
      if (this.credential == null) {
        this.credential = new KeyStoreCredential(this.file, this.type,
          Optional.ofNullable(this.password).map(String::toCharArray).orElse(null), this.alias,
          Optional.ofNullable(this.keyPassword).map(String::toCharArray).orElse(null));
        this.credential.afterPropertiesSet();
      }
      return this.credential;
    }

  }

}
