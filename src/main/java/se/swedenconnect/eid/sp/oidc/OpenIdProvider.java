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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * An OpenID Provider that the RP can send requests to, together with its discovery document.
 *
 * @author Martin Lindström
 */
public class OpenIdProvider {

  /**
   * Where the OP comes from.
   */
  public enum Source {
    /** Configured manually under {@code rp.providers}. */
    MANUAL,
    /** Found through the OpenID Federation. */
    FEDERATION
  }

  /** The issuer identifier. */
  private final @NonNull String issuer;

  /** The entity identifier (the issuer for manually configured OPs). */
  private final @NonNull String entityId;

  /** When the OP's metadata expires (only for OPs found through the federation). */
  private final @Nullable Instant expiresAt;

  /** The discovery document as JSON. */
  private final @NonNull JSONObject document;

  /** The parsed discovery document. */
  private final @NonNull OIDCProviderMetadata metadata;

  /** Where the OP comes from. */
  private final @NonNull Source source;

  /** Display names, where the language tag is the key (the empty string for an untagged value). */
  private final @NonNull Map<String, String> displayNames;

  /** Descriptions, where the language tag is the key (the empty string for an untagged value). */
  private final @NonNull Map<String, String> descriptions;

  /** Logotypes, where the language tag is the key (the empty string for an untagged value). */
  private final @NonNull Map<String, String> logos;

  /** The trust marks of the OP (only for OPs found through the federation). */
  private final @NonNull List<String> trustMarkTypes;

  /**
   * Constructor.
   *
   * @param document the discovery document
   * @param source where the OP comes from
   * @param trustMarkTypes the OP's trust mark types (empty for manually configured OPs)
   * @throws ParseException if the document is not a valid discovery document
   */
  public OpenIdProvider(final @NonNull JSONObject document, final @NonNull Source source,
      final @NonNull List<String> trustMarkTypes) throws ParseException {
    this(document, source, trustMarkTypes, null, null);
  }

  /**
   * Constructor.
   *
   * @param document the discovery document (or resolved {@code openid_provider} metadata)
   * @param source where the OP comes from
   * @param trustMarkTypes the OP's trust mark types (empty for manually configured OPs)
   * @param entityId the entity identifier ({@code null} means the issuer)
   * @param expiresAt when the metadata expires ({@code null} for no expiry)
   * @throws ParseException if the document is not a valid discovery document
   */
  public OpenIdProvider(final @NonNull JSONObject document, final @NonNull Source source,
      final @NonNull List<String> trustMarkTypes, final @Nullable String entityId,
      final @Nullable Instant expiresAt) throws ParseException {
    this.document = Objects.requireNonNull(document, "document must be set");
    this.metadata = OIDCProviderMetadata.parse(document);
    this.issuer = this.metadata.getIssuer().getValue();
    this.entityId = entityId != null ? entityId : this.issuer;
    this.expiresAt = expiresAt;
    this.source = Objects.requireNonNull(source, "source must be set");
    this.trustMarkTypes = List.copyOf(trustMarkTypes);
    this.displayNames = languageValues(document, "display_name");
    this.descriptions = languageValues(document, "description");
    this.logos = languageValues(document, "logo_uri");
  }

  /**
   * Gets the display names, where the language tag is the key and the empty string is used for an untagged value.
   *
   * @return a map of display names
   */
  public @NonNull Map<String, String> getDisplayNames() {
    return Collections.unmodifiableMap(this.displayNames);
  }

  /**
   * Gets the descriptions, where the language tag is the key and the empty string is used for an untagged value.
   *
   * @return a map of descriptions
   */
  public @NonNull Map<String, String> getDescriptions() {
    return Collections.unmodifiableMap(this.descriptions);
  }

  /**
   * Gets the logotype to use for a language.
   *
   * @param language the language
   * @return the logotype URI, or {@code null}
   */
  public @Nullable String getLogo(final @NonNull String language) {
    return Optional.ofNullable(this.logos.get(language))
        .or(() -> Optional.ofNullable(this.logos.get("")))
        .orElseGet(() -> this.logos.values().stream().findFirst().orElse(null));
  }

  /**
   * Tells whether the OP lists the given scope in {@code scopes_supported}.
   *
   * @param scope the scope
   * @return {@code true} if the scope is supported
   */
  public boolean supportsScope(final @NonNull String scope) {
    return this.getStringList("scopes_supported").contains(scope);
  }

  /**
   * Reads all values for a parameter that may be language tagged ({@code name} and {@code name#lang}).
   *
   * @param document the JSON document
   * @param name the parameter name
   * @return a map where the language tag is the key (the empty string for an untagged value)
   */
  private static @NonNull Map<String, String> languageValues(final @NonNull JSONObject document,
      final @NonNull String name) {
    final Map<String, String> values = new HashMap<>();
    for (final Map.Entry<String, Object> e : document.entrySet()) {
      if (!(e.getValue() instanceof final String value) || value.isBlank()) {
        continue;
      }
      if (e.getKey().equals(name)) {
        values.put("", value);
      }
      else if (e.getKey().startsWith(name + "#")) {
        values.put(e.getKey().substring(name.length() + 1), value);
      }
    }
    return values;
  }

  /**
   * Gets a string list from the discovery document.
   *
   * @param name the parameter name
   * @return the list (empty if not present)
   */
  public @NonNull List<String> getStringList(final @NonNull String name) {
    final Object value = this.document.get(name);
    if (value instanceof final JSONArray array) {
      return array.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    if (value instanceof final List<?> list) {
      return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    return List.of();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "%s [%s]".formatted(this.issuer, this.source);
  }

  /**
   * Gets the issuer identifier.
   *
   * @return the issuer identifier
   */
  public @NonNull String getIssuer() {
    return this.issuer;
  }

  /**
   * Gets the entity identifier.
   *
   * @return the entity identifier
   */
  public @NonNull String getEntityId() {
    return this.entityId;
  }

  /**
   * Gets when the OP's metadata expires.
   *
   * @return when the OP's metadata expires
   */
  public @Nullable Instant getExpiresAt() {
    return this.expiresAt;
  }

  /**
   * Gets the discovery document as JSON.
   *
   * @return the discovery document as JSON
   */
  public @NonNull JSONObject getDocument() {
    return this.document;
  }

  /**
   * Gets the parsed discovery document.
   *
   * @return the parsed discovery document
   */
  public @NonNull OIDCProviderMetadata getMetadata() {
    return this.metadata;
  }

  /**
   * Gets where the OP comes from.
   *
   * @return where the OP comes from
   */
  public @NonNull Source getSource() {
    return this.source;
  }

  /**
   * Gets the trust mark types of the OP.
   *
   * @return the trust mark types of the OP
   */
  public @NonNull List<String> getTrustMarkTypes() {
    return this.trustMarkTypes;
  }

}
