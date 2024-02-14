/*
 * Copyright 2018-2023 Sweden Connect
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
package se.swedenconnect.eid.sp.saml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.sweid.saml2.discovery.SwedishEidDiscoveryMatchingRules;

/**
 * Interface for the list of IdP:s that should be displayed for the user.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Slf4j
public class IdpList {

  /** The default time to keep an IdP list in the cache (10 minutes). */
  public static int DEFAULT_CACHE_TIME = 600;

  /** The metadata provider from where we get the IdP:s. */
  private final MetadataProvider metadataProvider;

  /** The SP metadata. */
  private final EntityDescriptor spMetadata;

  /** Statically configured IdP:s. */
  private final List<StaticIdpDiscoEntry> staticIdps;

  /** List of black listed IdPs. */
  private final List<String> blackList;

  /** Should IdP:s we display only the static IdP entries? */
  private final boolean includeOnlyStatic;

  /** Is the Holder-of-key profile active? */
  private final boolean hokActive;

  /** The SP entity categories. */
  private final List<String> spEntityCategories;

  /** The time (in seconds) to keep the cache. */
  private int cacheTime = DEFAULT_CACHE_TIME;

  /** Setting that tells whether we should ignore contract entity categories when matching. */
  private boolean ignoreContracts = true;

  /** The IdP list cache. */
  private List<IdpDiscoveryInformation> cache = null;

  /** The last time the cache was updated. */
  private long lastUpdate = 0;

  /**
   * Constructor.
   *
   * @param metadataProvider the metadata provider
   * @param spMetadata the SP metadata
   * @param staticIdps statically configured IdP:s
   * @param blackList list of black listed IdPs
   * @param includeOnlyStatic should IdP:s we display only the static IdP entries?
   * @param hokActive is the Holder-of-key profile active?
   */
  public IdpList(final MetadataProvider metadataProvider,
      final EntityDescriptor spMetadata,
      final List<StaticIdpDiscoEntry> staticIdps,
      final List<String> blackList,
      final boolean includeOnlyStatic,
      final boolean hokActive) {
    this.metadataProvider = Objects.requireNonNull(metadataProvider, "metadataProvider must be assigned");
    this.spMetadata = Objects.requireNonNull(spMetadata, "spMetadata must be assigned");
    this.staticIdps = Optional.ofNullable(staticIdps).orElseGet(() -> Collections.emptyList());
    this.blackList = Optional.ofNullable(blackList).orElseGet(() -> Collections.emptyList());
    this.includeOnlyStatic = includeOnlyStatic;
    this.hokActive = hokActive;

    this.spEntityCategories = EntityDescriptorUtils.getEntityCategories(this.spMetadata).stream()
        // Remove all loa4 entity categories if we don't support HoK
        .filter(c -> this.hokActive || (!this.hokActive && !c.contains("loa4")))
        .collect(Collectors.toList());

    //this.getIdps();
  }

  /**
   * Returns a list of IdP:s that should be displayed for the user.
   *
   * @return a list of IdPs
   */
  public synchronized List<IdpDiscoveryInformation> getIdps() {
    if (this.validCache()) {
      return this.cache;
    }
    log.debug("Compiling IdP list from metadata {}", this.metadataProvider.getID());

    final List<IdpDiscoveryInformation> idpList = new ArrayList<>();

    // First read the statically configured IdP:s ...
    //
    int pos = 0;
    for (final StaticIdpDiscoEntry idpEntry : this.staticIdps) {
      try {
        if (!idpEntry.isEnabled()) {
          log.debug("IdP '{}' is disabled in configuration and will be excluded from IdP list", idpEntry.getEntityId());
          continue;
        }
        if (this.blackList.contains(idpEntry.getEntityId())) {
          log.debug("IdP '{}' is black-listed in configuration and will be excluded from IdP list", idpEntry.getEntityId());
          continue;
        }
        final EntityDescriptor idp =
            this.metadataProvider.getEntityDescriptor(idpEntry.getEntityId(), IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        if (idp == null) {
          log.warn("No metadata for statically configured IdP {} found", idpEntry.getEntityId());
          continue;
        }

        idpList.add(new IdpDiscoveryInformation(idp, idpEntry, pos++));
      }
      catch (final ResolverException e) {
        log.error("Error getting IdP '%s' from metadata".formatted(idpEntry.getEntityId()));
      }
    }
    // Next, add the rest of the IdP:s ...
    //
    if (idpList.isEmpty() || !this.includeOnlyStatic) {

      final Iterable<EntityDescriptor> it = this.metadataProvider.iterator(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
      it.forEach(idp -> {
        if (this.staticIdps.stream().anyMatch(e -> e.getEntityId().equals(idp.getEntityID()))) {
          return;
        }
        if (this.blackList.contains(idp.getEntityID())) {
          log.debug("IdP '{}' is black-listed in configuration and will be excluded from IdP list", idp.getEntityID());
          return;
        }
        if (this.isValidIdP(idp)) {
          idpList.add(new IdpDiscoveryInformation(idp));
        }
        else {
          log.debug("IdP '{}' removed from IdP listing - no matching entity categories", idp.getEntityID());
        }

      });

    }

    // Sort the IdP list
    //
    Collections.sort(idpList, Comparator.comparing(IdpDiscoveryInformation::getSortOrder));

    this.cache = Collections.unmodifiableList(idpList);
    this.lastUpdate = System.currentTimeMillis();

    log.debug("Returning IdP list: {}", this.cache);
    return this.cache;
  }

  /**
   * Matches the SP entity categories against the IdP to check if the IdP can be used by the SP.
   *
   * @param idp the IdP metadata
   * @return true if the IdP can be used, and false otherwise
   */
  protected boolean isValidIdP(final EntityDescriptor idp) {
    final List<String> idpEntityCategories = EntityDescriptorUtils.getEntityCategories(idp);
    if (!SwedishEidDiscoveryMatchingRules.isServiceEntityMatch(this.spEntityCategories, idpEntityCategories)) {
      return false;
    }
    if (!this.ignoreContracts) {
      if (!SwedishEidDiscoveryMatchingRules.isServiceContractMatch(this.spEntityCategories, idpEntityCategories)) {
        return false;
      }
    }
    if (!SwedishEidDiscoveryMatchingRules.isServicePropertyMatch(this.spEntityCategories, idpEntityCategories)) {
      return false;
    }
    return true;
  }

  /**
   * Predicate that checks if the cache is still valid.
   *
   * @return {@code true} if the cache is still valid and {@code false} otherwise
   */
  private boolean validCache() {
    if (this.cache == null || this.lastUpdate == 0) {
      return false;
    }
    if (this.includeOnlyStatic) {
      return true;
    }
    return System.currentTimeMillis() - this.lastUpdate > this.cacheTime * 1000L;
  }

  /**
   * Assigns the cache time.
   *
   * @param cacheTime the cache time (in seconds)
   */
  public void setCacheTime(final int cacheTime) {
    this.cacheTime = cacheTime;
  }

  /**
   * Setting that tells whether we should ignore contract entity categories when matching.
   *
   * @param ignoreContracts whether to ignore contract entity categories
   */
  public void setIgnoreContracts(final boolean ignoreContracts) {
    this.ignoreContracts = ignoreContracts;
  }

  /**
   * Represents a IdP discovery info entry.
   */
  @Data
  @ToString
  public static class StaticIdpDiscoEntry implements InitializingBean {

    /**
     * Is the IdP entry enabled?
     */
    private boolean enabled = true;

    /**
     * The entity ID for the IdP.
     */
    private String entityId;

    /**
     * The Swedish display name.
     */
    private String displayNameSv;

    /**
     * The Swedish description.
     */
    private String descriptionSv;

    /**
     * The English display name.
     */
    private String displayNameEn;

    /**
     * The English description.
     */
    private String descriptionEn;

    /**
     * The logotype URL.
     */
    private String logoUrl;

    /**
     * Logotype width (in pixels).
     */
    private Integer logoWidth;

    /**
     * Logotype height (in pixels).
     */
    private Integer logoHeight;


    @Override
    public void afterPropertiesSet() throws Exception {
      Assert.hasText(this.entityId, "entity-id for static IdP entry not assigned");
    }

  }

}
