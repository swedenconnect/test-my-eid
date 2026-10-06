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

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.web.util.UriComponentsBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Client for the OpenID Federation endpoints: entity configurations, subordinate listing, resolve and trust marks.
 *
 * @author Martin Lindström
 */
public class FederationClient {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationClient.class);

  /** HTTP timeout. */
  private static final int HTTP_TIMEOUT_MILLIS = 10_000;

  /**
   * Gets the URL of an entity's entity configuration.
   *
   * @param entityId the entity identifier
   * @return the URL
   */
  public static @NonNull URI entityConfigurationUrl(final @NonNull String entityId) {
    final String base = entityId.endsWith("/") ? entityId.substring(0, entityId.length() - 1) : entityId;
    return URI.create(base + EntityConfigurationService.WELL_KNOWN_PATH);
  }

  /**
   * Fetches an entity configuration.
   *
   * @param entityId the entity identifier
   * @return the signed entity configuration (not verified)
   * @throws FederationException for errors
   */
  public @NonNull SignedJWT fetchEntityConfiguration(final @NonNull String entityId) throws FederationException {
    return this.getJwt(entityConfigurationUrl(entityId), "entity configuration for " + entityId);
  }

  /**
   * Calls a resolve endpoint.
   *
   * @param resolveEndpoint the resolve endpoint
   * @param subject the entity to resolve
   * @param trustAnchor the trust anchor
   * @param entityType the entity type ({@code null} for all types)
   * @return the resolve response (not verified)
   * @throws FederationException for errors
   */
  public @NonNull SignedJWT resolve(final @NonNull URI resolveEndpoint, final @NonNull String subject,
      final @NonNull String trustAnchor, final @Nullable String entityType) throws FederationException {
    final UriComponentsBuilder builder = UriComponentsBuilder.fromUri(resolveEndpoint)
        .queryParam("sub", subject)
        .queryParam("trust_anchor", trustAnchor);
    if (entityType != null) {
      builder.queryParam("entity_type", entityType);
    }
    return this.getJwt(builder.build().encode().toUri(), "resolve response for " + subject);
  }

  /**
   * Calls a subordinate listing endpoint.
   *
   * @param listEndpoint the listing endpoint
   * @param entityType the entity type to list
   * @return the entity identifiers
   * @throws FederationException for errors
   */
  public @NonNull List<String> list(final @NonNull URI listEndpoint, final @NonNull String entityType)
      throws FederationException {
    final URI url = UriComponentsBuilder.fromUri(listEndpoint)
        .queryParam("entity_type", entityType)
        .build()
        .encode()
        .toUri();
    final String body = this.get(url, "subordinate listing");
    try {
      return JSONArrayUtils.parse(body).stream()
          .filter(String.class::isInstance)
          .map(String.class::cast)
          .toList();
    }
    catch (final ParseException e) {
      throw new FederationException("Invalid subordinate listing from %s - %s".formatted(url, e.getMessage()), e);
    }
  }

  /**
   * Calls a trust mark endpoint.
   *
   * @param trustMarkEndpoint the trust mark endpoint
   * @param trustMarkType the trust mark type
   * @param subject the entity the trust mark is issued to
   * @return the trust mark (not verified)
   * @throws FederationException for errors
   */
  public @NonNull SignedJWT fetchTrustMark(final @NonNull URI trustMarkEndpoint, final @NonNull String trustMarkType,
      final @NonNull String subject) throws FederationException {
    final URI url = UriComponentsBuilder.fromUri(trustMarkEndpoint)
        .queryParam("trust_mark_type", trustMarkType)
        .queryParam("sub", subject)
        .build()
        .encode()
        .toUri();
    return this.getJwt(url, "trust mark " + trustMarkType);
  }

  /**
   * Gets a signed JWT.
   *
   * @param url the URL
   * @param what what is fetched (for error messages)
   * @return the signed JWT
   * @throws FederationException for errors
   */
  private @NonNull SignedJWT getJwt(final @NonNull URI url, final @NonNull String what) throws FederationException {
    final String body = this.get(url, what);
    try {
      return SignedJWT.parse(body);
    }
    catch (final java.text.ParseException e) {
      throw new FederationException("The %s from %s is not a signed JWT".formatted(what, url), e);
    }
  }

  /**
   * Makes a GET request.
   *
   * @param url the URL
   * @param what what is fetched (for error messages)
   * @return the response body
   * @throws FederationException for errors
   */
  private @NonNull String get(final @NonNull URI url, final @NonNull String what) throws FederationException {
    log.debug("Fetching {} from {}", what, url);
    try {
      final HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET, url);
      request.setConnectTimeout(HTTP_TIMEOUT_MILLIS);
      request.setReadTimeout(HTTP_TIMEOUT_MILLIS);
      final HTTPResponse response = request.send();
      if (response.getStatusCode() != HTTPResponse.SC_OK) {
        throw new FederationException("Failed to get %s from %s - HTTP status %d: %s".formatted(
            what, url, response.getStatusCode(), Objects.toString(response.getBody(), "")));
      }
      final String body = response.getBody();
      if (body == null || body.isBlank()) {
        throw new FederationException("Empty response for %s from %s".formatted(what, url));
      }
      return body.trim();
    }
    catch (final IOException e) {
      throw new FederationException("Failed to get %s from %s - %s".formatted(what, url, e.getMessage()), e);
    }
  }

  /**
   * Gets a federation endpoint from {@code federation_entity} metadata.
   *
   * @param metadata the {@code metadata} claim
   * @param parameter the endpoint parameter, e.g. {@code federation_resolve_endpoint}
   * @return the endpoint, or {@code null}
   */
  static @Nullable URI federationEndpoint(final @Nullable Map<String, Object> metadata,
      final @NonNull String parameter) {
    if (metadata == null || !(metadata.get("federation_entity") instanceof final Map<?, ?> fe)) {
      return null;
    }
    final Object endpoint = fe.get(parameter);
    return endpoint instanceof final String s && !s.isBlank() ? URI.create(s) : null;
  }

  /**
   * Exception for federation errors.
   */
  public static class FederationException extends Exception {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructor.
     *
     * @param message the error message
     */
    public FederationException(final @NonNull String message) {
      super(message);
    }

    /**
     * Constructor.
     *
     * @param message the error message
     * @param cause the cause
     */
    public FederationException(final @NonNull String message, final @NonNull Throwable cause) {
      super(message, cause);
    }
  }

}
