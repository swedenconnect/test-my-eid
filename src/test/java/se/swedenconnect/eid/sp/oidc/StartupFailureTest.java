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
package se.swedenconnect.eid.sp.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import se.swedenconnect.eid.sp.TestMyEidApplication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Makes sure that the application does not start with invalid OIDC settings, and that the error message tells what
 * is wrong.
 */
class StartupFailureTest {

  private static final String TA_JWKS = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"ta\","
      + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]}";

  private static Throwable start(final String... properties) {
    final Throwable t = catchThrowable(() -> {
      try (final ConfigurableApplicationContext ctx = new SpringApplicationBuilder(TestMyEidApplication.class)
          .profiles("test")
          .properties("server.port=0")
          .properties(properties)
          .run()) {
        // Started - should not happen
      }
    });
    assertThat(t).as("The application should not start").isNotNull();
    return t;
  }

  private static String messages(final Throwable t) {
    final StringBuilder sb = new StringBuilder();
    for (Throwable c = t; c != null; c = c.getCause()) {
      sb.append(c.getMessage()).append('\n');
    }
    return sb.toString();
  }

  @Test
  void federationWithoutFederationKey() {
    assertThat(messages(start("rp.federation.enabled=true",
        "rp.federation.trust-anchor.entity-id=https://ta.example.com",
        "rp.federation.trust-anchor.jwks=" + TA_JWKS)))
        .contains("rp.credential.federation must be assigned");
  }

  @Test
  void federationWithoutTrustAnchorKey() {
    assertThat(messages(start("rp.federation.enabled=true",
        "rp.federation.trust-anchor.entity-id=https://ta.example.com")))
        .contains("rp.federation.trust-anchor.jwks or jwks-resource");
  }

  @Test
  void encryptionWithDisallowedAlgorithm() {
    assertThat(messages(start("rp.encryption.enabled=true", "rp.encryption.id-token-alg=RSA1_5")))
        .contains("rp.encryption.id-token-alg has the value 'RSA1_5'");
  }

  @Test
  void missingClientNameInEnglish() {
    assertThat(messages(start("rp.metadata.client-names[0]=sv-Testa")))
        .contains("'en' is missing");
  }

  @Test
  void missingContactEmail() {
    assertThat(messages(start("rp.metadata.contacts[0]=no-email")))
        .contains("contact email");
  }

}
