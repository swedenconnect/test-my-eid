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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;

/**
 * JOSE helpers for the OIDC Relying Party: algorithm selection according to the Sweden Connect security requirements,
 * JWK creation, signers and decrypters.
 *
 * @author Martin Lindström
 */
public final class JoseSupport {

  /** The JWS algorithms that the Sweden Connect security requirements allow. */
  public static final @NonNull Set<JWSAlgorithm> ALLOWED_SIGNATURE_ALGORITHMS = Set.of(
      JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
      JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

  /** The JWE key management algorithms that the Sweden Connect trust anchor policy allows. */
  public static final @NonNull List<JWEAlgorithm> ALLOWED_KEY_MANAGEMENT_ALGORITHMS = List.of(
      JWEAlgorithm.RSA_OAEP, JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.ECDH_ES);

  /** The JWE content encryption algorithms that the Sweden Connect trust anchor policy allows. */
  public static final @NonNull List<EncryptionMethod> ALLOWED_CONTENT_ENCRYPTION_ALGORITHMS = List.of(
      EncryptionMethod.A128CBC_HS256, EncryptionMethod.A256CBC_HS512,
      EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);

  /** The default content encryption algorithm. */
  public static final @NonNull EncryptionMethod DEFAULT_CONTENT_ENCRYPTION_ALGORITHM = EncryptionMethod.A256GCM;

  // Hidden constructor
  private JoseSupport() {
  }

  /**
   * Gets the strongest signature algorithm that the Sweden Connect security requirements allow for the credential's
   * key: {@code RS512} for an RSA key, and for an EC key the algorithm matching its curve.
   *
   * @param credential the signing credential
   * @return the JWS algorithm
   * @throws IllegalArgumentException for unsupported keys
   */
  public static @NonNull JWSAlgorithm signatureAlgorithm(final @NonNull PkiCredential credential) {
    final PublicKey key = credential.getPublicKey();
    if (key instanceof RSAPublicKey) {
      return JWSAlgorithm.RS512;
    }
    if (key instanceof final ECPublicKey ecKey) {
      final Curve curve = Curve.forECParameterSpec(ecKey.getParams());
      if (Curve.P_256.equals(curve)) {
        return JWSAlgorithm.ES256;
      }
      if (Curve.P_384.equals(curve)) {
        return JWSAlgorithm.ES384;
      }
      if (Curve.P_521.equals(curve)) {
        return JWSAlgorithm.ES512;
      }
      throw new IllegalArgumentException("Unsupported EC curve: " + curve);
    }
    throw new IllegalArgumentException("Unsupported key type for signing: " + key.getAlgorithm());
  }

  /**
   * Gets the default key management algorithm for a decryption credential: {@code RSA-OAEP-256} for an RSA key and
   * {@code ECDH-ES} for an EC key.
   *
   * @param credential the decryption credential
   * @return the JWE algorithm
   * @throws IllegalArgumentException for unsupported keys
   */
  public static @NonNull JWEAlgorithm defaultKeyManagementAlgorithm(final @NonNull PkiCredential credential) {
    final PublicKey key = credential.getPublicKey();
    if (key instanceof RSAPublicKey) {
      return JWEAlgorithm.RSA_OAEP_256;
    }
    if (key instanceof ECPublicKey) {
      return JWEAlgorithm.ECDH_ES;
    }
    throw new IllegalArgumentException("Unsupported key type for decryption: " + key.getAlgorithm());
  }

  /**
   * Tells whether the key management algorithm can be used with the credential's key type.
   *
   * @param algorithm the key management algorithm
   * @param credential the decryption credential
   * @return {@code true} if the algorithm fits the key type
   */
  public static boolean fitsKeyType(final @NonNull JWEAlgorithm algorithm, final @NonNull PkiCredential credential) {
    if (credential.getPublicKey() instanceof RSAPublicKey) {
      return JWEAlgorithm.Family.RSA.contains(algorithm);
    }
    if (credential.getPublicKey() instanceof ECPublicKey) {
      return JWEAlgorithm.Family.ECDH_ES.contains(algorithm);
    }
    return false;
  }

  /**
   * Creates the public JWK for a credential, declared for the given use. The key ID is the JWK thumbprint (SHA-256).
   *
   * @param credential the credential
   * @param use the key use
   * @param algorithm the algorithm to declare (may be {@code null})
   * @return a public JWK holding a {@code kid}
   */
  public static @NonNull JWK publicJwk(final @NonNull PkiCredential credential, final @NonNull KeyUse use,
      final com.nimbusds.jose.@Nullable Algorithm algorithm) {
    try {
      final PublicKey key = credential.getPublicKey();
      if (key instanceof final RSAPublicKey rsaKey) {
        return new RSAKey.Builder(rsaKey)
            .keyUse(use)
            .algorithm(algorithm)
            .keyIDFromThumbprint()
            .build();
      }
      if (key instanceof final ECPublicKey ecKey) {
        return new ECKey.Builder(Curve.forECParameterSpec(ecKey.getParams()), ecKey)
            .keyUse(use)
            .algorithm(algorithm)
            .keyIDFromThumbprint()
            .build();
      }
    }
    catch (final JOSEException e) {
      throw new IllegalArgumentException("Failed to create JWK - " + e.getMessage(), e);
    }
    throw new IllegalArgumentException("Unsupported key type: " + credential.getPublicKey().getAlgorithm());
  }

  /**
   * Creates a signer for the credential.
   *
   * @param credential the signing credential
   * @return a {@link JWSSigner}
   * @throws JOSEException for unsupported keys
   */
  public static @NonNull JWSSigner signer(final @NonNull PkiCredential credential) throws JOSEException {
    final PrivateKey key = credential.getPrivateKey();
    if (key instanceof final ECPrivateKey ecKey) {
      return new ECDSASigner(ecKey);
    }
    if (key instanceof final RSAPrivateKey rsaKey) {
      return new RSASSASigner(rsaKey);
    }
    throw new JOSEException("Unsupported key type for signing: " + key.getAlgorithm());
  }

  /**
   * Creates a decrypter for the credential.
   *
   * @param credential the decryption credential
   * @return a {@link JWEDecrypter}
   * @throws JOSEException for unsupported keys
   */
  public static @NonNull JWEDecrypter decrypter(final @NonNull PkiCredential credential) throws JOSEException {
    final PrivateKey key = credential.getPrivateKey();
    if (key instanceof final ECPrivateKey ecKey) {
      return new ECDHDecrypter(ecKey);
    }
    if (key instanceof final RSAPrivateKey rsaKey) {
      return new RSADecrypter(rsaKey);
    }
    throw new JOSEException("Unsupported key type for decryption: " + key.getAlgorithm());
  }

}
