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
package se.swedenconnect.eid.sp.oidc.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.jspecify.annotations.NonNull;
import se.swedenconnect.eid.sp.oidc.JoseSupport;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Verifies the signature of a signed JWT against a set of keys. Only the algorithms that the Sweden Connect security
 * requirements allow are accepted.
 *
 * @author Martin Lindström
 */
public final class JwtVerifier {

  /** Creates verifiers. */
  private static final DefaultJWSVerifierFactory verifierFactory = new DefaultJWSVerifierFactory();

  // Hidden constructor
  private JwtVerifier() {
  }

  /**
   * Verifies the signature of the JWT. The key whose {@code kid} matches the JWT's {@code kid} is tried first, and
   * then the other keys.
   *
   * @param jwt the JWT
   * @param keys the keys
   * @return {@code true} if the signature is valid
   */
  public static boolean verify(final @NonNull SignedJWT jwt, final @NonNull JWKSet keys) {
    if (!JoseSupport.ALLOWED_SIGNATURE_ALGORITHMS.contains(jwt.getHeader().getAlgorithm())) {
      return false;
    }
    for (final JWK jwk : candidateKeys(jwt, keys)) {
      try {
        if (!(jwk instanceof final AsymmetricJWK asymmetric)) {
          continue;
        }
        final JWSVerifier verifier = verifierFactory.createJWSVerifier(jwt.getHeader(), asymmetric.toPublicKey());
        if (jwt.verify(verifier)) {
          return true;
        }
      }
      catch (final JOSEException e) {
        // Try the next key
      }
    }
    return false;
  }

  /**
   * Orders the keys so that the key with a matching {@code kid} comes first.
   *
   * @param jwt the JWT
   * @param keys the keys
   * @return the candidate keys
   */
  private static @NonNull List<JWK> candidateKeys(final @NonNull SignedJWT jwt, final @NonNull JWKSet keys) {
    final List<JWK> candidates = new ArrayList<>();
    Optional.ofNullable(jwt.getHeader().getKeyID()).map(keys::getKeyByKeyId).ifPresent(candidates::add);
    keys.getKeys().stream().filter(k -> !candidates.contains(k)).forEach(candidates::add);
    return candidates;
  }

}
