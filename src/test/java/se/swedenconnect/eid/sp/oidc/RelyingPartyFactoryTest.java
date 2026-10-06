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
import com.nimbusds.jose.jwk.KeyUse;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.CredentialsConfiguration.PkiCredentialConfiguration;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.security.credential.PkiCredential;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link RelyingPartyFactory}.
 */
class RelyingPartyFactoryTest {

  private RelyingParty create(final SpConfigurationProperties sp, final RpConfigurationProperties rp,
      final PkiCredential sign, final PkiCredential decrypt,
      final Map<PkiCredentialConfiguration, PkiCredential> others) {
    return RelyingPartyFactory.create(sp, rp, "/", TestSupport.loader(sp, sign, decrypt, others));
  }

  private RelyingParty create(final SpConfigurationProperties sp, final RpConfigurationProperties rp) {
    return this.create(sp, rp, TestSupport.rsaCredential(), TestSupport.rsaCredential(), Map.of());
  }

  @Test
  void defaults() throws Exception {
    final RelyingParty rp = this.create(TestSupport.spProperties(), new RpConfigurationProperties());
    assertThat(rp.getEntityId()).isEqualTo("https://test.example.com");
    assertThat(rp.getClientId().getValue()).isEqualTo("https://test.example.com");
    assertThat(rp.getRedirectUri().toString()).isEqualTo("https://test.example.com/oidc/callback");
    assertThat(rp.isEncryptionEnabled()).isFalse();

    final JSONObject md = rp.getMetadataJson();
    RpMetadataAssertions.assertMeetsSwedenConnectRequirements(md);
    assertThat(md.get("organization_identifier")).isEqualTo("urn:glue:iso6523:0007:2021006883");
    assertThat(md.get("contacts")).isEqualTo(List.of("operations@example.com"));
    final JWKSet jwks = JWKSet.parse((Map<String, Object>) md.get("jwks"));
    assertThat(jwks.getKeys()).hasSize(1);
    assertThat(jwks.getKeys().getFirst().getKeyUse()).isEqualTo(KeyUse.SIGNATURE);

    // The federation key falls back to the signing key when federation is disabled
    assertThat(rp.getFederationJwk().getKeyID()).isEqualTo(rp.getSignJwk().getKeyID());
  }

  @Test
  void contextPathAndEntityIdOverride() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    RelyingParty rp = RelyingPartyFactory.create(sp, new RpConfigurationProperties(), "/testmyeid",
        TestSupport.loader(sp, TestSupport.rsaCredential(), TestSupport.rsaCredential(), Map.of()));
    assertThat(rp.getEntityId()).isEqualTo("https://test.example.com/testmyeid");
    assertThat(rp.getRedirectUri().toString()).isEqualTo("https://test.example.com/testmyeid/oidc/callback");
    assertThat(rp.getMetadataJson().get("logo_uri")).isEqualTo("https://test.example.com/testmyeid/images/logo.svg");
    assertThat(rp.getMetadataJson().get("client_uri")).isEqualTo("https://test.example.com/testmyeid/");

    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.setEntityId("https://test.example.com/rp");
    rp = this.create(sp, props);
    assertThat(rp.getEntityId()).isEqualTo("https://test.example.com/rp");
  }

  @ParameterizedTest
  @CsvSource({ "secp256r1,ES256", "secp384r1,ES384", "secp521r1,ES512" })
  void ecSigningAlgorithm(final String curve, final String alg) {
    final RelyingParty rp = this.create(TestSupport.spProperties(), new RpConfigurationProperties(),
        TestSupport.ecCredential(curve), TestSupport.rsaCredential(), Map.of());
    assertThat(rp.getSignatureAlgorithm().getName()).isEqualTo(alg);
    assertThat(rp.getMetadataJson().get("request_object_signing_alg")).isEqualTo(alg);
    assertThat(rp.getMetadataJson().get("token_endpoint_auth_signing_alg")).isEqualTo(alg);
  }

  @Test
  void rsaSigningAlgorithm() {
    final RelyingParty rp = this.create(TestSupport.spProperties(), new RpConfigurationProperties());
    assertThat(rp.getSignatureAlgorithm().getName()).isEqualTo("RS512");
  }

  @Test
  void oidcCredentialsOverrideSpCredentials() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    final RpConfigurationProperties props = new RpConfigurationProperties();
    final PkiCredentialConfiguration signConfig = new PkiCredentialConfiguration();
    props.getCredential().setSign(signConfig);
    final PkiCredential ec = TestSupport.ecCredential("secp256r1");
    final RelyingParty rp = this.create(sp, props, TestSupport.rsaCredential(), TestSupport.rsaCredential(),
        Map.of(signConfig, ec));
    assertThat(rp.getSignCredential()).isSameAs(ec);
  }

  @Test
  void federationEnabledRequiresFederationKey() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getFederation().setEnabled(true);
    assertThatThrownBy(() -> this.create(TestSupport.spProperties(), props))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("rp.credential.federation");
  }

  @Test
  void federationKeyIsUsedWhenGiven() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getFederation().setEnabled(true);
    final PkiCredentialConfiguration fedConfig = new PkiCredentialConfiguration();
    props.getCredential().setFederation(fedConfig);
    final PkiCredential fed = TestSupport.newRsaCredential();
    final RelyingParty rp = this.create(TestSupport.spProperties(), props, TestSupport.rsaCredential(),
        TestSupport.rsaCredential(), Map.of(fedConfig, fed));
    assertThat(rp.getFederationCredential()).isSameAs(fed);
    assertThat(rp.getFederationJwk().getKeyID()).isNotEqualTo(rp.getSignJwk().getKeyID());
    assertThat(rp.getMetadataJson().get("client_registration_types")).isEqualTo(List.of("automatic"));
  }

  @Test
  void encryptionDefaults() throws Exception {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getEncryption().setEnabled(true);
    final PkiCredential decrypt = TestSupport.newRsaCredential();
    final RelyingParty rp = this.create(TestSupport.spProperties(), props, TestSupport.rsaCredential(), decrypt,
        Map.of());
    final JSONObject md = rp.getMetadataJson();
    RpMetadataAssertions.assertMeetsSwedenConnectRequirements(md);
    assertThat(md.get("id_token_encrypted_response_alg")).isEqualTo("RSA-OAEP-256");
    assertThat(md.get("id_token_encrypted_response_enc")).isEqualTo("A256GCM");
    assertThat(md.get("userinfo_encrypted_response_alg")).isEqualTo("RSA-OAEP-256");
    assertThat(md.get("userinfo_encrypted_response_enc")).isEqualTo("A256GCM");
    final JWKSet jwks = JWKSet.parse((Map<String, Object>) md.get("jwks"));
    assertThat(jwks.getKeys()).hasSize(2);
    final JWK encKey = jwks.getKeys().stream().filter(k -> KeyUse.ENCRYPTION.equals(k.getKeyUse())).findFirst()
        .orElseThrow();
    assertThat(encKey.getKeyID()).isNotBlank();
  }

  @Test
  void encryptionDefaultsForEcKey() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getEncryption().setEnabled(true);
    final RelyingParty rp = this.create(TestSupport.spProperties(), props, TestSupport.rsaCredential(),
        TestSupport.ecCredential("secp256r1"), Map.of());
    assertThat(rp.getMetadataJson().get("id_token_encrypted_response_alg")).isEqualTo("ECDH-ES");
  }

  @Test
  void encryptionConfiguredValues() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getEncryption().setEnabled(true);
    props.getEncryption().setIdTokenAlg("RSA-OAEP");
    props.getEncryption().setIdTokenEnc("A128CBC-HS256");
    props.getEncryption().setUserinfoAlg("RSA-OAEP-256");
    props.getEncryption().setUserinfoEnc("A256CBC-HS512");
    final RelyingParty rp = this.create(TestSupport.spProperties(), props);
    assertThat(rp.getMetadataJson().get("id_token_encrypted_response_alg")).isEqualTo("RSA-OAEP");
    assertThat(rp.getMetadataJson().get("id_token_encrypted_response_enc")).isEqualTo("A128CBC-HS256");
    assertThat(rp.getMetadataJson().get("userinfo_encrypted_response_enc")).isEqualTo("A256CBC-HS512");
  }

  @ParameterizedTest
  @CsvSource({ "RSA1_5,", "A128KW,", ",A192GCM", ",A192CBC-HS384" })
  void encryptionDisallowedAlgorithms(final String alg, final String enc) {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getEncryption().setEnabled(true);
    props.getEncryption().setIdTokenAlg(alg);
    props.getEncryption().setIdTokenEnc(enc);
    assertThatThrownBy(() -> this.create(TestSupport.spProperties(), props))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("only");
  }

  @Test
  void encryptionAlgorithmMustFitKeyType() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getEncryption().setEnabled(true);
    props.getEncryption().setUserinfoAlg("ECDH-ES");
    assertThatThrownBy(() -> this.create(TestSupport.spProperties(), props))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("can not be used with the decryption key");
  }

  @Test
  void encryptionWithoutDecryptionCredential() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    // Not possible through configuration (sp.credential.decrypt is required), but the factory checks it
    org.springframework.test.util.ReflectionTestUtils.setField(sp.getCredential(), "decrypt", null);
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getEncryption().setEnabled(true);
    assertThatThrownBy(() -> this.create(sp, props))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("no decryption credential");
  }

  @Test
  void missingContacts() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    sp.getMetadata().setContactPersons(null);
    assertThatThrownBy(() -> this.create(sp, new RpConfigurationProperties()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("contact email");

    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getMetadata().setContacts(List.of("rp@example.com"));
    assertThat(this.create(sp, props).getMetadataJson().get("contacts")).isEqualTo(List.of("rp@example.com"));
  }

  @Test
  void missingEnglishClientName() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    sp.getMetadata().setServiceNames(List.of(new LocalizedString("Testa ditt eID", "sv")));
    assertThatThrownBy(() -> this.create(sp, new RpConfigurationProperties()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("'en' is missing");
  }

  @Test
  void clientNameOverride() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getMetadata().setClientNames(List.of(new LocalizedString("RP sv", "sv"), new LocalizedString("RP en", "en")));
    final JSONObject md = this.create(TestSupport.spProperties(), props).getMetadataJson();
    assertThat(md.get("client_name#sv")).isEqualTo("RP sv");
    assertThat(md.get("client_name#en")).isEqualTo("RP en");
  }

  @Test
  void missingLogo() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    sp.getMetadata().getUiinfo().setLogos(List.of());
    assertThatThrownBy(() -> this.create(sp, new RpConfigurationProperties()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("logo_uri");
  }

  @Test
  void logoMustBeHttps() {
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getMetadata().setLogoUri("http://example.com/logo.svg");
    assertThatThrownBy(() -> this.create(TestSupport.spProperties(), props))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("HTTPS");
  }

  @Test
  void organizationIdentifier() {
    final SpConfigurationProperties sp = TestSupport.spProperties();
    sp.getMetadata().getOrganization().setNumber("12345");
    assertThat(this.create(sp, new RpConfigurationProperties()).getMetadataJson())
        .doesNotContainKey("organization_identifier");

    sp.getMetadata().getOrganization().setNumber("202100-6883");
    assertThat(this.create(sp, new RpConfigurationProperties()).getMetadataJson().get("organization_identifier"))
        .isEqualTo("urn:glue:iso6523:0007:2021006883");

    sp.getMetadata().getOrganization().setNumber("12345");
    final RpConfigurationProperties props = new RpConfigurationProperties();
    props.getMetadata().setOrganizationIdentifier("urn:glue:iso6523:0007:5566778899");
    assertThat(this.create(sp, props).getMetadataJson().get("organization_identifier"))
        .isEqualTo("urn:glue:iso6523:0007:5566778899");
  }

  @Test
  void organizationNames() {
    final JSONObject md = this.create(TestSupport.spProperties(), new RpConfigurationProperties()).getMetadataJson();
    assertThat(md.get("organization_name#sv")).isEqualTo("Sweden Connect");
    assertThat(md.get("organization_name#en")).isEqualTo("Sweden Connect");
  }

  @Test
  void contactsAreDeduplicated() {
    final JSONObject md = this.create(TestSupport.spProperties(), new RpConfigurationProperties()).getMetadataJson();
    assertThat(md.get("contacts")).isEqualTo(List.of("operations@example.com"));
  }

}
