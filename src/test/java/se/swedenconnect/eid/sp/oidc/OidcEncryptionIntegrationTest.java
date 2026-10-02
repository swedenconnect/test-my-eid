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

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the OIDC authentication flow with encryption of ID tokens and UserInfo responses turned on.
 */
@SpringBootTest(properties = "rp.encryption.enabled=true")
@ActiveProfiles("test")
class OidcEncryptionIntegrationTest extends OidcFlowTestBase {

  private static final TestOidcProvider OP;

  static {
    try {
      OP = new TestOidcProvider();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @DynamicPropertySource
  static void properties(final DynamicPropertyRegistry registry) {
    registry.add("rp.providers[0].issuer", OP::getIssuer);
  }

  @AfterAll
  static void stop() throws Exception {
    OP.close();
  }

  @Override
  protected TestOidcProvider op() {
    return OP;
  }

  private RSAKey rpEncryptionKey() {
    return (RSAKey) JoseSupport.publicJwk(Objects.requireNonNull(this.relyingParty.getDecryptCredential()),
        KeyUse.ENCRYPTION, null);
  }

  @Test
  void encryptedResponses() throws Exception {
    OP.rpEncryptionKey = this.rpEncryptionKey();
    final String html = this.authenticate();
    assertThat(html).contains("197705232382");
  }

  @Test
  void unencryptedIdTokenIsRejected() {
    OP.rpEncryptionKey = null;
    assertThat(this.expectApplicationError(null).getCause()).hasMessageContaining("not encrypted");
  }

}
