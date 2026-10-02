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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Checks RP metadata against the Sweden Connect OIDC profile (Section 3.2) and the Sweden Connect metadata
 * requirements (Sections 3 and 4).
 */
final class RpMetadataAssertions {

  private RpMetadataAssertions() {
  }

  /**
   * Asserts that the metadata meets the Sweden Connect requirements for an RP.
   *
   * @param rp the RP metadata
   * @throws Exception for parse errors
   */
  @SuppressWarnings("unchecked")
  static void assertMeetsSwedenConnectRequirements(final JSONObject rp) throws Exception {
    assertThat((List<?>) rp.get("redirect_uris")).isNotEmpty();
    assertThat((List<Object>) rp.get("response_types")).contains("code");
    assertThat((List<Object>) rp.get("grant_types")).contains("authorization_code");
    assertThat(rp.get("token_endpoint_auth_method")).isEqualTo("private_key_jwt");
    assertThat((String) rp.get("client_name#sv")).isNotBlank();
    assertThat((String) rp.get("client_name#en")).isNotBlank();
    assertThat(URI.create((String) rp.get("client_uri")).getScheme()).isEqualTo("https");
    assertThat(URI.create((String) rp.get("logo_uri")).getScheme()).isEqualTo("https");
    assertThat((List<?>) rp.get("contacts")).anyMatch(c -> c.toString().contains("@"));
    assertThat(rp.get("subject_type")).isIn("public", "pairwise");
    assertThat(rp).doesNotContainKeys("jwks_uri", "id_token_signed_response_alg", "userinfo_signed_response_alg");

    @SuppressWarnings("unchecked")
    final JWKSet jwks = JWKSet.parse((Map<String, Object>) rp.get("jwks"));
    assertThat(jwks.getKeys()).isNotEmpty();
    for (final JWK key : jwks.getKeys()) {
      assertThat(key.getKeyID()).isNotBlank();
      assertThat(key.getKeyUse()).isNotNull();
      assertThat(key.isPrivate()).isFalse();
    }
    if (rp.containsKey("organization_identifier")) {
      assertThat((String) rp.get("organization_identifier")).matches("urn:glue:iso6523:0007:\\d{10}");
    }
    for (final String p : List.of("request_object_signing_alg", "token_endpoint_auth_signing_alg")) {
      if (rp.containsKey(p)) {
        assertThat(rp.get(p)).isIn("RS256", "RS384", "RS512", "ES256", "ES384", "ES512");
      }
    }
    for (final String p : List.of("id_token_encrypted_response_alg", "userinfo_encrypted_response_alg")) {
      if (rp.containsKey(p)) {
        assertThat(rp.get(p)).isIn("RSA-OAEP", "RSA-OAEP-256", "ECDH-ES");
      }
    }
    for (final String p : List.of("id_token_encrypted_response_enc", "userinfo_encrypted_response_enc")) {
      if (rp.containsKey(p)) {
        assertThat(rp.get(p)).isIn("A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM");
      }
    }
  }

}
