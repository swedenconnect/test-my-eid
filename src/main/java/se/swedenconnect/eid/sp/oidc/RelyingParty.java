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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import se.swedenconnect.security.credential.PkiCredential;

import java.net.URI;
import java.util.Objects;

/**
 * The OpenID Connect Relying Party of Test my eID. There is one RP, used both for authentication and signature
 * approval.
 *
 * @author Martin Lindström
 */
public class RelyingParty {

  /** The path of the redirect URI (relative to the base URI and context path). */
  public static final @NonNull String CALLBACK_PATH = "/oidc/callback";

  /** The RP's entity identifier. */
  private final @NonNull String entityId;

  /** The redirect URI used for all requests. */
  private final @NonNull URI redirectUri;

  /** The OIDC signing credential. */
  private final @NonNull PkiCredential signCredential;

  /** The public JWK of the signing credential. */
  private final @NonNull JWK signJwk;

  /** The algorithm used for Request Objects and token endpoint assertions. */
  private final @NonNull JWSAlgorithm signatureAlgorithm;

  /** The OIDC decryption credential. */
  private final @Nullable PkiCredential decryptCredential;

  /** Whether ID tokens and UserInfo responses are encrypted. */
  private final boolean encryptionEnabled;

  /** The federation entity credential. */
  private final @NonNull PkiCredential federationCredential;

  /** The public JWK of the federation entity credential. */
  private final @NonNull JWK federationJwk;

  /** The algorithm used to sign the entity configuration. */
  private final @NonNull JWSAlgorithm federationAlgorithm;

  /** The RP metadata. */
  private final @NonNull OIDCClientMetadata metadata;

  /**
   * Constructor.
   *
   * @param entityId the entity identifier (and client ID)
   * @param redirectUri the redirect URI
   * @param signCredential the OIDC signing credential
   * @param decryptCredential the OIDC decryption credential
   * @param encryptionEnabled whether encryption is turned on
   * @param federationCredential the federation entity credential
   * @param metadata the RP metadata
   */
  public RelyingParty(final @NonNull String entityId, final @NonNull URI redirectUri,
      final @NonNull PkiCredential signCredential, final @Nullable PkiCredential decryptCredential,
      final boolean encryptionEnabled, final @NonNull PkiCredential federationCredential,
      final @NonNull OIDCClientMetadata metadata) {
    this.entityId = Objects.requireNonNull(entityId, "entityId must be set");
    this.redirectUri = Objects.requireNonNull(redirectUri, "redirectUri must be set");
    this.signCredential = Objects.requireNonNull(signCredential, "signCredential must be set");
    this.signatureAlgorithm = JoseSupport.signatureAlgorithm(signCredential);
    this.signJwk = JoseSupport.publicJwk(signCredential, com.nimbusds.jose.jwk.KeyUse.SIGNATURE,
        this.signatureAlgorithm);
    this.decryptCredential = decryptCredential;
    this.encryptionEnabled = encryptionEnabled;
    this.federationCredential = Objects.requireNonNull(federationCredential, "federationCredential must be set");
    this.federationAlgorithm = JoseSupport.signatureAlgorithm(federationCredential);
    this.federationJwk = JoseSupport.publicJwk(federationCredential, com.nimbusds.jose.jwk.KeyUse.SIGNATURE,
        this.federationAlgorithm);
    this.metadata = Objects.requireNonNull(metadata, "metadata must be set");
  }

  /**
   * Gets the client ID, which is the entity identifier.
   *
   * @return the client ID
   */
  public @NonNull ClientID getClientId() {
    return new ClientID(this.entityId);
  }

  /**
   * Gets the RP metadata.
   *
   * @return the metadata
   */
  public @NonNull OIDCClientMetadata getMetadata() {
    return this.metadata;
  }

  /**
   * Gets the RP metadata as a JSON object, as it is published in the entity configuration.
   *
   * @return a JSON object
   */
  public @NonNull JSONObject getMetadataJson() {
    return this.metadata.toJSONObject(true);
  }

  /**
   * Gets the federation JWK set published in the entity configuration.
   *
   * @return a JWK set holding the federation key
   */
  public @NonNull JWKSet getFederationJwkSet() {
    return new JWKSet(this.federationJwk);
  }

  /**
   * Gets the RP's entity identifier.
   *
   * @return the RP's entity identifier
   */
  public @NonNull String getEntityId() {
    return this.entityId;
  }

  /**
   * Gets the redirect URI used for all requests.
   *
   * @return the redirect URI used for all requests
   */
  public @NonNull URI getRedirectUri() {
    return this.redirectUri;
  }

  /**
   * Gets the OIDC signing credential.
   *
   * @return the OIDC signing credential
   */
  public @NonNull PkiCredential getSignCredential() {
    return this.signCredential;
  }

  /**
   * Gets the public JWK of the signing credential.
   *
   * @return the public JWK of the signing credential
   */
  public @NonNull JWK getSignJwk() {
    return this.signJwk;
  }

  /**
   * Gets the algorithm used for Request Objects and token endpoint assertions.
   *
   * @return the algorithm used for Request Objects and token endpoint assertions
   */
  public @NonNull JWSAlgorithm getSignatureAlgorithm() {
    return this.signatureAlgorithm;
  }

  /**
   * Gets the OIDC decryption credential.
   *
   * @return the OIDC decryption credential
   */
  public @Nullable PkiCredential getDecryptCredential() {
    return this.decryptCredential;
  }

  /**
   * Tells whether ID tokens and UserInfo responses are encrypted.
   *
   * @return {@code true} if ID tokens and UserInfo responses are encrypted
   */
  public boolean isEncryptionEnabled() {
    return this.encryptionEnabled;
  }

  /**
   * Gets the federation entity credential.
   *
   * @return the federation entity credential
   */
  public @NonNull PkiCredential getFederationCredential() {
    return this.federationCredential;
  }

  /**
   * Gets the public JWK of the federation entity credential.
   *
   * @return the public JWK of the federation entity credential
   */
  public @NonNull JWK getFederationJwk() {
    return this.federationJwk;
  }

  /**
   * Gets the algorithm used to sign the entity configuration.
   *
   * @return the algorithm used to sign the entity configuration
   */
  public @NonNull JWSAlgorithm getFederationAlgorithm() {
    return this.federationAlgorithm;
  }

}
