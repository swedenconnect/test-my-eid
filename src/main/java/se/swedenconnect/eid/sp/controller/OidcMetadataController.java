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
package se.swedenconnect.eid.sp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties;
import se.swedenconnect.eid.sp.oidc.RelyingParty;
import se.swedenconnect.eid.sp.oidc.RelyingPartyFactory;
import se.swedenconnect.eid.sp.oidc.federation.EntityConfigurationService;

/**
 * Publishes the RP's entity configuration at {@code <entity identifier>/.well-known/openid-federation}, and its
 * {@code metadata} claim as JSON at {@code /oidc/metadata}.
 *
 * @author Martin Lindström
 */
@Controller
public class OidcMetadataController implements InitializingBean {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcMetadataController.class);

  /** The path where the metadata claim is published. */
  public static final @NonNull String METADATA_PATH = "/oidc/metadata";

  /** The entity configuration service. */
  private final EntityConfigurationService entityConfigurationService;

  /** The Relying Party. */
  private final RelyingParty relyingParty;

  /** The application URI (base URI plus context path). */
  private final String applicationUri;

  /** The handler mapping where the entity configuration endpoint is registered. */
  private final RequestMappingHandlerMapping handlerMapping;

  /**
   * Constructor.
   *
   * @param entityConfigurationService the entity configuration service
   * @param relyingParty the Relying Party
   * @param spProperties the SP settings
   * @param contextPath the servlet context path
   * @param handlerMapping the handler mapping
   */
  public OidcMetadataController(final @NonNull EntityConfigurationService entityConfigurationService,
      final @NonNull RelyingParty relyingParty, final @NonNull SpConfigurationProperties spProperties,
      @Value("${server.servlet.context-path:/}") final @NonNull String contextPath,
      @Qualifier("requestMappingHandlerMapping") final @NonNull RequestMappingHandlerMapping handlerMapping) {
    this.entityConfigurationService = entityConfigurationService;
    this.relyingParty = relyingParty;
    this.applicationUri = RelyingPartyFactory.applicationUri(spProperties.getBaseUri(), contextPath);
    this.handlerMapping = handlerMapping;
  }

  /**
   * Registers the entity configuration endpoint, whose path is given by the entity identifier.
   *
   * @throws Exception if the entity identifier can not be served by this application
   */
  @Override
  public void afterPropertiesSet() throws Exception {
    final String path = this.entityConfigurationPath();
    this.handlerMapping.registerMapping(
        RequestMappingInfo.paths(path).methods(RequestMethod.GET).build(),
        this, OidcMetadataController.class.getMethod("getEntityConfiguration"));
    log.info("Entity configuration published at {}{}", this.relyingParty.getEntityId(),
        EntityConfigurationService.WELL_KNOWN_PATH);
  }

  /**
   * Gets the path (relative to the context path) of the entity configuration endpoint.
   *
   * @return the path
   */
  @NonNull String entityConfigurationPath() {
    String entityId = this.relyingParty.getEntityId();
    if (entityId.endsWith("/")) {
      entityId = entityId.substring(0, entityId.length() - 1);
    }
    if (!entityId.startsWith(this.applicationUri)) {
      throw new IllegalStateException(("The RP entity identifier '%s' must start with the application URI '%s' so "
          + "that its entity configuration can be published").formatted(entityId, this.applicationUri));
    }
    return entityId.substring(this.applicationUri.length()) + EntityConfigurationService.WELL_KNOWN_PATH;
  }

  /**
   * Returns the signed entity configuration.
   *
   * @return the entity configuration
   */
  @ResponseBody
  public @NonNull ResponseEntity<String> getEntityConfiguration() {
    return ResponseEntity.ok()
        .header("Cache-Control", "no-cache, no-store")
        .contentType(MediaType.parseMediaType(EntityConfigurationService.ENTITY_STATEMENT_MEDIA_TYPE))
        .body(this.entityConfigurationService.getEntityConfiguration().serialize());
  }

  /**
   * Returns the {@code metadata} claim of the entity configuration as JSON. Operators of manually configured OPs use
   * this to register the RP.
   *
   * @return the metadata
   */
  @GetMapping(value = METADATA_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public @NonNull ResponseEntity<String> getMetadata() {
    return ResponseEntity.ok()
        .header("Cache-Control", "no-cache, no-store")
        .contentType(MediaType.APPLICATION_JSON)
        .body(this.entityConfigurationService.getMetadata().toJSONString());
  }

}
