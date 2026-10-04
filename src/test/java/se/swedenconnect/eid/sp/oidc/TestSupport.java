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

import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.CredentialsConfiguration.PkiCredentialConfiguration;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.Duration;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Helpers for the OIDC tests.
 */
public final class TestSupport {

  /** Cached RSA credential. */
  private static PkiCredential rsa;

  private TestSupport() {
  }

  /**
   * Gets an RSA credential (2048 bits).
   *
   * @return a credential
   */
  public static synchronized PkiCredential rsaCredential() {
    if (rsa == null) {
      rsa = newRsaCredential();
    }
    return rsa;
  }

  /**
   * Creates a new RSA credential (2048 bits).
   *
   * @return a credential
   */
  public static PkiCredential newRsaCredential() {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      return new BasicCredential(gen.generateKeyPair());
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates an EC credential.
   *
   * @param curve the curve name, e.g. {@code secp256r1}
   * @return a credential
   */
  public static PkiCredential ecCredential(final String curve) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec(curve));
      return new BasicCredential(gen.generateKeyPair());
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates SP settings that resemble the default {@code application.yml}.
   *
   * @return SP settings
   */
  public static SpConfigurationProperties spProperties() {
    final SpConfigurationProperties sp = new SpConfigurationProperties();
    sp.setBaseUri("https://test.example.com");
    sp.setEntityId("http://test.example.com/testmyeid");
    sp.getCredential().setSign(new PkiCredentialConfiguration());
    sp.getCredential().setDecrypt(new PkiCredentialConfiguration());

    final MetadataConfiguration md = sp.getMetadata();
    md.setServiceNames(List.of(new LocalizedString("Testa ditt eID", "sv"),
        new LocalizedString("Test your eID", "en")));
    final MetadataConfiguration.UIInfoConfig uiInfo = new MetadataConfiguration.UIInfoConfig();
    final MetadataConfiguration.UIInfoConfig.UIInfoLogo logo = new MetadataConfiguration.UIInfoConfig.UIInfoLogo();
    logo.setPath("/images/logo.svg");
    uiInfo.setLogos(List.of(logo));
    uiInfo.setDisplayNames(List.of(new LocalizedString("Testa mitt eID", "sv")));
    md.setUiinfo(uiInfo);

    final MetadataConfiguration.ContactPersonConfig support = new MetadataConfiguration.ContactPersonConfig();
    support.setEmailAddress("operations@example.com");
    final MetadataConfiguration.ContactPersonConfig technical = new MetadataConfiguration.ContactPersonConfig();
    technical.setEmailAddress("operations@example.com");
    md.setContactPersons(Map.of(ContactPersonTypeEnumeration.SUPPORT, support,
        ContactPersonTypeEnumeration.TECHNICAL, technical));

    final MetadataConfiguration.OrganizationConfig org = new MetadataConfiguration.OrganizationConfig();
    org.setNames(List.of(new LocalizedString("Sweden Connect", "sv"), new LocalizedString("Sweden Connect", "en")));
    org.setNumber("2021006883");
    md.setOrganization(org);
    return sp;
  }

  /**
   * Creates a credential loader that maps the SP sign/decrypt configuration objects to the given credentials, and any
   * other configuration object according to the supplied map.
   *
   * @param sp the SP settings
   * @param sign the signing credential
   * @param decrypt the decryption credential
   * @param others other mappings
   * @return a loader
   */
  public static Function<PkiCredentialConfiguration, PkiCredential> loader(final SpConfigurationProperties sp,
      final PkiCredential sign, final PkiCredential decrypt,
      final Map<PkiCredentialConfiguration, PkiCredential> others) {
    final Map<PkiCredentialConfiguration, PkiCredential> map = new IdentityHashMap<>(others);
    map.put(sp.getCredential().getSign(), sign);
    if (sp.getCredential().getDecrypt() != null) {
      map.put(sp.getCredential().getDecrypt(), decrypt);
    }
    return c -> {
      final PkiCredential credential = map.get(c);
      if (credential == null) {
        throw new IllegalStateException("No credential for configuration");
      }
      return credential;
    };
  }

  /**
   * Creates a Relying Party with default settings.
   *
   * @return a Relying Party
   */
  public static RelyingParty relyingParty() {
    final SpConfigurationProperties sp = spProperties();
    return RelyingPartyFactory.create(sp, new RpConfigurationProperties(), "/",
        loader(sp, rsaCredential(), rsaCredential(), Map.of()));
  }

  /**
   * Decodes a Base64-encoded message (user message or sign message) into its UTF-8 string. Fails if the value is not
   * a string holding valid Base64.
   *
   * @param value the encoded value
   * @return the decoded message
   */
  public static String decode(final Object value) {
    if (!(value instanceof final String s)) {
      throw new AssertionError("Expected a string but got " + value);
    }
    return new String(java.util.Base64.getDecoder().decode(s), java.nio.charset.StandardCharsets.UTF_8);
  }

  /**
   * A clock that can be moved.
   */
  public static class MutableClock extends Clock {

    private Instant now;

    /**
     * Constructor.
     *
     * @param now the start time
     */
    public MutableClock(final Instant now) {
      this.now = now;
    }

    /**
     * Moves the clock.
     *
     * @param duration the duration to move
     */
    public void advance(final Duration duration) {
      this.now = this.now.plus(duration);
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return this.now;
    }
  }

}
