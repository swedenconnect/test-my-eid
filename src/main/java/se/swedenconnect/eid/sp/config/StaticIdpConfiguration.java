/*
 * Copyright 2018 Sweden Connect
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
import java.util.List;
import java.util.Optional;

import javax.annotation.PostConstruct;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@Component
@PropertySource(ignoreResourceNotFound = true, value = "${sp.discovery.static-idp-configuration}")
@ConfigurationProperties
@ToString
@Data
@Slf4j
public class StaticIdpConfiguration {

  /** Should IdP:s not listed in this configuration be part of the IdP Selection page? */
  private Boolean includeUnlisted = Boolean.TRUE;

  /** List of statically defined IdP:s. */
  private List<StaticIdpDiscoEntry> idp;

  /** List of black listed IdPs. */
  private List<String> blackList;

  public List<StaticIdpDiscoEntry> getIdps() {
    return this.idp != null ? this.idp : Collections.emptyList();
  }

  /**
   * Predicate that tells if the given IdP is black-listed and should not be included.
   * 
   * @param entityID
   *          the IdP entityID
   * @return {@code true} if the IdP is black-listed, and {@code false} otherwise
   */
  public boolean isBlackListed(String entityID) {
    return this.blackList != null ? this.blackList.contains(entityID) : false;
  }

  public Optional<StaticIdpDiscoEntry> getIdpDiscoInformation(String entityID) {
    Assert.notNull(entityID, "entityID must not be null");
    return this.getIdps().stream().filter(i -> entityID.equals(i.getEntityId())).findFirst();
  }

  @PostConstruct
  public void init() {
    log.info("StaticIdpConfiguration: {}", this.toString());
  }

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
    private Boolean enabled = Boolean.TRUE;
    private Boolean skipEntityCategoryMatching = Boolean.FALSE;
    
    public boolean isEnabled() {
      return this.enabled != null ? this.enabled.booleanValue() : true;
    }
    
    public boolean isSkipEntityCategoryMatching() {
      return this.skipEntityCategoryMatching != null ? this.skipEntityCategoryMatching.booleanValue() : false;
    }
  }

}
