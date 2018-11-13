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
package se.swedenconnect.eid.sp.config;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.annotation.PostConstruct;

import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.springframework.core.io.Resource;

import lombok.Data;
import se.litsec.opensaml.utils.KeyStoreUtils;

/**
 * Representation of a credential.
 * 
 * @author Martin Lindström (martin@litsec.se)
 */
@Data
public class SpCredential {

  private Resource file;
  private String type;
  private String password;
  private String alias;
  private String keyPassword;

  private X509Credential credential;

  @PostConstruct
  void setup() throws Exception {
    KeyStore keyStore = KeyStoreUtils.loadKeyStore(this.file.getInputStream(), this.password,
        this.type != null ? this.type : KeyStore.getDefaultType());
    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(this.alias,
        new KeyStore.PasswordProtection(this.keyPassword.toCharArray()));

    this.credential = new BasicX509Credential((X509Certificate) entry.getCertificate(), entry.getPrivateKey());
  }

}
