/*
 * Copyright 2018-2021 Sweden Connect
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
package se.swedenconnect.eid.sp.config;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

/**
 * Configuration class for statically configured IdPs.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Component
@PropertySource(ignoreResourceNotFound = true, value = "${sp.discovery.static-idp-configuration}")
@ConfigurationProperties
@ToString
@Data
@Slf4j
public class StaticIdpConfiguration {

  /** Should IdP:s not listed in this configuration be part of the IdP Selection page? */
  private Boolean includeUnlisted = Boolean.TRUE;

  /** Statically defined IdP:s. */
  private Map<String, StaticIdpDiscoEntry> idp;

  /** List of black listed IdPs. */
  private List<String> blackList;

  /**
   * Returns a list of IdP discovery info objects based on their sortOrder property.
   *
   * @return a (possibly empty) list of discovery objects
   */
  public List<StaticIdpDiscoEntry> getIdps() {
    return this.idp != null
        ? this.idp.values().stream().sorted(Comparator.comparing(StaticIdpDiscoEntry::getSortOrder)).collect(Collectors.toList())
        : Collections.emptyList();
  }

  /**
   * Predicate that tells if the given IdP is black-listed and should not be included.
   *
   * @param entityID
   *          the IdP entityID
   * @return true if the IdP is black-listed, and false otherwise
   */
  public boolean isBlackListed(final String entityID) {
    return this.blackList != null ? this.blackList.contains(entityID) : false;
  }

  /**
   * Returns the IdP discovery information for the given entityID.
   *
   * @param entityID
   *          the IdP entityID
   * @return an optional to a StaticIdpDiscoEntry object
   */
  public Optional<StaticIdpDiscoEntry> getIdpDiscoInformation(final String entityID) {
    Assert.notNull(entityID, "entityID must not be null");
    return this.idp != null
        ? this.idp.values().stream().filter(i -> entityID.equals(i.getEntityId())).findFirst()
        : Optional.empty();
  }

  /**
   * Logs the static IdP configuration.
   */
  @PostConstruct
  public void init() {
    log.info("Static IdP configuration: {}", this.toString());
  }

  /**
   * Represents a IdP discovery info entry.
   */
  @Data
  @ToString
  public static class StaticIdpDiscoEntry {
    private String entityId;
    private Integer sortOrder = Integer.MAX_VALUE;
    private String displayNameSv;
    private String descriptionSv;
    private String displayNameEn;
    private String descriptionEn;
    private String logoUrl;
    private Integer logoWidth;
    private Integer logoHeight;
    private Boolean mobileUse;
    private Boolean enabled = Boolean.TRUE;
    private Boolean skipEntityCategoryMatching = Boolean.FALSE;

    /**
     * Predicate that tells if the IdP is enabled.
     *
     * @return true if the IdP is enabled, and false otherwise
     */
    public boolean isEnabled() {
      return this.enabled != null ? this.enabled.booleanValue() : true;
    }

    /**
     * Predicate that tells whether we should skip discovery entity category matching for the entry.
     *
     * @return true if matching should be skipped, and false otherwise
     */
    public boolean isSkipEntityCategoryMatching() {
      return this.skipEntityCategoryMatching != null ? this.skipEntityCategoryMatching.booleanValue() : false;
    }
  }

}
