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
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.eid.sp.oidc.JoseSupport;
import se.swedenconnect.eid.sp.oidc.RelyingParty;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Creates and caches the RP's signed entity configuration. The cached statement is signed anew when half of its
 * lifetime has passed, or when its content changes.
 *
 * @author Martin Lindström
 */
public class EntityConfigurationService {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(EntityConfigurationService.class);

  /** The media type for entity statements (OpenID Federation). */
  public static final @NonNull String ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt";

  /** The JOSE type for entity statements. */
  public static final @NonNull JOSEObjectType ENTITY_STATEMENT_TYPE = EntityStatement.JOSE_OBJECT_TYPE;

  /** The well-known path for the entity configuration. */
  public static final @NonNull String WELL_KNOWN_PATH = "/.well-known/openid-federation";

  /** The Relying Party. */
  private final @NonNull RelyingParty relyingParty;

  /** The lifetime of an entity configuration. */
  private final @NonNull Duration lifetime;

  /** The clock. */
  private final @NonNull Clock clock;

  /** Supplies the authority hints (empty when federation is disabled). */
  private @NonNull Supplier<List<String>> authorityHintsSupplier = List::of;

  /** Supplies the trust marks to publish (empty when federation is disabled). */
  private @NonNull Supplier<List<JSONObject>> trustMarksSupplier = List::of;

  /** The cached entity configuration. */
  private @Nullable Cached cached;

  /**
   * Constructor.
   *
   * @param relyingParty the Relying Party
   * @param lifetime the lifetime of a signed entity configuration
   * @param clock the clock
   */
  public EntityConfigurationService(final @NonNull RelyingParty relyingParty, final @NonNull Duration lifetime,
      final @NonNull Clock clock) {
    this.relyingParty = Objects.requireNonNull(relyingParty, "relyingParty must be set");
    this.lifetime = Objects.requireNonNull(lifetime, "lifetime must be set");
    this.clock = Objects.requireNonNull(clock, "clock must be set");
  }

  /**
   * Gets the signed entity configuration. The cached statement is returned unless half of its lifetime has passed or
   * its content has changed.
   *
   * @return the signed entity configuration
   */
  public synchronized @NonNull SignedJWT getEntityConfiguration() {
    final Map<String, Object> content = this.createContent();
    final Instant now = this.clock.instant();
    if (this.cached != null && this.cached.content().equals(content) && now.isBefore(this.cached.renewAt())) {
      return this.cached.jwt();
    }
    if (this.cached != null && !this.cached.content().equals(content)) {
      log.debug("Content of entity configuration for '{}' has changed - signing anew",
          this.relyingParty.getEntityId());
    }
    final SignedJWT jwt = this.sign(content, now);
    this.cached = new Cached(content, jwt, now.plus(this.lifetime.dividedBy(2)));
    return jwt;
  }

  /**
   * Gets the {@code metadata} claim of the entity configuration.
   *
   * @return the metadata as a JSON object
   */
  public @NonNull JSONObject getMetadata() {
    final JSONObject metadata = new JSONObject();
    metadata.put("openid_relying_party", this.relyingParty.getMetadataJson());
    return metadata;
  }

  /**
   * Creates the content of the entity configuration, i.e., all claims except those that change with every signing.
   *
   * @return the content
   */
  private @NonNull Map<String, Object> createContent() {
    final Map<String, Object> content = new LinkedHashMap<>();
    content.put("iss", this.relyingParty.getEntityId());
    content.put("sub", this.relyingParty.getEntityId());
    content.put("jwks", this.relyingParty.getFederationJwkSet().toPublicJWKSet().toJSONObject(true));
    content.put("metadata", this.getMetadata());

    final List<String> authorityHints = this.authorityHintsSupplier.get();
    if (authorityHints != null && !authorityHints.isEmpty()) {
      final JSONArray hints = new JSONArray();
      hints.addAll(authorityHints);
      content.put("authority_hints", hints);
    }
    final List<JSONObject> trustMarks = this.trustMarksSupplier.get();
    if (trustMarks != null && !trustMarks.isEmpty()) {
      final JSONArray marks = new JSONArray();
      marks.addAll(trustMarks);
      content.put("trust_marks", marks);
    }
    return content;
  }

  /**
   * Signs the entity configuration.
   *
   * @param content the content
   * @param now the current time
   * @return the signed JWT
   */
  private @NonNull SignedJWT sign(final @NonNull Map<String, Object> content, final @NonNull Instant now) {
    try {
      final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
      content.forEach(builder::claim);
      builder.issueTime(Date.from(now))
          .expirationTime(Date.from(now.plus(this.lifetime)))
          .jwtID(UUID.randomUUID().toString());

      final JWSHeader header = new JWSHeader.Builder(this.relyingParty.getFederationAlgorithm())
          .type(ENTITY_STATEMENT_TYPE)
          .keyID(this.relyingParty.getFederationJwk().getKeyID())
          .build();
      final SignedJWT jwt = new SignedJWT(header, builder.build());
      jwt.sign(JoseSupport.signer(this.relyingParty.getFederationCredential()));
      log.debug("Signed entity configuration for '{}' [exp={}]", this.relyingParty.getEntityId(),
          now.plus(this.lifetime));
      return jwt;
    }
    catch (final JOSEException e) {
      throw new IllegalStateException("Failed to sign entity configuration - " + e.getMessage(), e);
    }
  }

  /**
   * A cached entity configuration.
   *
   * @param content the content it was created from
   * @param jwt the signed statement
   * @param renewAt when it should be signed anew
   */
  private record Cached(@NonNull Map<String, Object> content, @NonNull SignedJWT jwt, @NonNull Instant renewAt) {
  }

  /**
   * Assigns the supplier of the authority hints.
   *
   * @param authorityHintsSupplier the supplier of the authority hints
   */
  public void setAuthorityHintsSupplier(final @NonNull Supplier<List<String>> authorityHintsSupplier) {
    this.authorityHintsSupplier = authorityHintsSupplier;
  }

  /**
   * Assigns the supplier of the trust marks to publish.
   *
   * @param trustMarksSupplier the supplier of the trust marks to publish
   */
  public void setTrustMarksSupplier(final @NonNull Supplier<List<JSONObject>> trustMarksSupplier) {
    this.trustMarksSupplier = trustMarksSupplier;
  }

}
