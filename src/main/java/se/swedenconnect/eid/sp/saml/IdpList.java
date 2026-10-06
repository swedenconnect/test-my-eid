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
package se.swedenconnect.eid.sp.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.shibboleth.shared.resolver.ResolverException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation;
import se.swedenconnect.eid.sp.model.Protocol;
import se.swedenconnect.eid.sp.oidc.OpRegistry;
import se.swedenconnect.eid.sp.oidc.OpenIdProvider;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.sweid.saml2.discovery.SwedishEidDiscoveryMatchingRules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Interface for the list of IdP:s that should be displayed for the user.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class IdpList {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(IdpList.class);

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

  /** The OP registry (may be null). */
  private final @Nullable OpRegistry opRegistry;

  /** The IdP list cache (SAML entries only). */
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
  public IdpList(final @NonNull MetadataProvider metadataProvider,
      final @NonNull EntityDescriptor spMetadata,
      final @Nullable List<StaticIdpDiscoEntry> staticIdps,
      final @Nullable List<String> blackList,
      final boolean includeOnlyStatic,
      final boolean hokActive) {
    this(metadataProvider, spMetadata, staticIdps, blackList, includeOnlyStatic, hokActive, null);
  }

  /**
   * Constructor.
   *
   * @param metadataProvider the metadata provider
   * @param spMetadata the SP metadata
   * @param staticIdps statically configured IdP:s and OP:s
   * @param blackList list of black listed IdPs
   * @param includeOnlyStatic should we display only the static entries?
   * @param hokActive is the Holder-of-key profile active?
   * @param opRegistry the registry of OpenID Providers (may be {@code null})
   */
  public IdpList(final @NonNull MetadataProvider metadataProvider,
      final @NonNull EntityDescriptor spMetadata,
      final @Nullable List<StaticIdpDiscoEntry> staticIdps,
      final @Nullable List<String> blackList,
      final boolean includeOnlyStatic,
      final boolean hokActive,
      final @Nullable OpRegistry opRegistry) {
    this.opRegistry = opRegistry;
    this.metadataProvider = Objects.requireNonNull(metadataProvider, "metadataProvider must be assigned");
    this.spMetadata = Objects.requireNonNull(spMetadata, "spMetadata must be assigned");
    this.staticIdps = Optional.ofNullable(staticIdps).orElse(Collections.emptyList());
    this.blackList = Optional.ofNullable(blackList).orElse(Collections.emptyList());
    this.includeOnlyStatic = includeOnlyStatic;
    this.hokActive = hokActive;

    this.spEntityCategories = EntityDescriptorUtils.getEntityCategories(this.spMetadata).stream()
        // Remove all loa4 entity categories if we don't support HoK
        .filter(c -> this.hokActive || (!this.hokActive && !c.contains("loa4")))
        .collect(Collectors.toList());

    //this.getIdps();
  }

  /**
   * Returns a list of IdP:s and OP:s that should be displayed for the user. Statically configured entries come first,
   * in the configured order, followed by the remaining IdP:s and then the remaining OP:s (unless only static entries
   * should be displayed).
   *
   * @return a list of IdP:s and OP:s
   */
  public @NonNull List<IdpDiscoveryInformation> getIdps() {
    final List<IdpDiscoveryInformation> samlEntries = this.getSamlEntries();
    final List<IdpDiscoveryInformation> oidcEntries = this.getOidcEntries();

    final List<IdpDiscoveryInformation> list = new ArrayList<>();
    samlEntries.stream().filter(IdpDiscoveryInformation::isStaticEntry).forEach(list::add);
    oidcEntries.stream().filter(IdpDiscoveryInformation::isStaticEntry).forEach(list::add);
    list.sort(Comparator.comparing(IdpDiscoveryInformation::getSortOrder));

    if (list.isEmpty() || !this.includeOnlyStatic) {
      samlEntries.stream().filter(e -> !e.isStaticEntry()).forEach(list::add);
      oidcEntries.stream().filter(e -> !e.isStaticEntry()).forEach(list::add);
    }
    log.trace("Returning IdP/OP list: {}", list);
    return Collections.unmodifiableList(list);
  }

  /**
   * Returns the SAML IdP:s that may be displayed (cached).
   *
   * @return a list of IdP:s
   */
  private synchronized @NonNull List<IdpDiscoveryInformation> getSamlEntries() {
    if (this.validCache()) {
      return this.cache;
    }
    log.debug("Compiling IdP list from metadata {}", this.metadataProvider.getID());

    final List<IdpDiscoveryInformation> idpList = new ArrayList<>();

    // First read the statically configured IdP:s ...
    //
    for (int pos = 0; pos < this.staticIdps.size(); pos++) {
      final StaticIdpDiscoEntry idpEntry = this.staticIdps.get(pos);
      if (idpEntry.getProtocol() != Protocol.SAML) {
        continue;
      }
      try {
        if (!idpEntry.isEnabled()) {
          log.debug("IdP '{}' is disabled in configuration and will be excluded from IdP list", idpEntry.getEntityId());
          continue;
        }
        if (this.blackList.contains(idpEntry.getEntityId())) {
          log.debug("IdP '{}' is black-listed in configuration and will be excluded from IdP list",
              idpEntry.getEntityId());
          continue;
        }
        final EntityDescriptor idp =
            this.metadataProvider.getEntityDescriptor(idpEntry.getEntityId(), IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        if (idp == null) {
          log.warn("No metadata for statically configured IdP {} found", idpEntry.getEntityId());
          continue;
        }

        idpList.add(new IdpDiscoveryInformation(idp, idpEntry, pos));
      }
      catch (final ResolverException e) {
        log.error("Error getting IdP '%s' from metadata".formatted(idpEntry.getEntityId()));
      }
    }
    // Next, add the rest of the IdP:s ...
    //
    final Iterable<EntityDescriptor> it = this.metadataProvider.iterator(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    it.forEach(idp -> {
      if (this.staticIdps.stream()
          .anyMatch(e -> e.getProtocol() == Protocol.SAML && idp.getEntityID().equals(e.getEntityId()))) {
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

    this.cache = Collections.unmodifiableList(idpList);
    this.lastUpdate = System.currentTimeMillis();

    log.debug("IdP list: {}", this.cache);
    return this.cache;
  }

  /**
   * Returns the OpenID Providers that may be displayed.
   *
   * @return a list of OP:s
   */
  private @NonNull List<IdpDiscoveryInformation> getOidcEntries() {
    if (this.opRegistry == null) {
      return List.of();
    }
    final List<OpenIdProvider> providers = this.opRegistry.getProviders();
    final List<IdpDiscoveryInformation> entries = new ArrayList<>();
    for (final OpenIdProvider op : providers) {
      StaticIdpDiscoEntry staticEntry = null;
      int pos = 0;
      for (; pos < this.staticIdps.size(); pos++) {
        final StaticIdpDiscoEntry e = this.staticIdps.get(pos);
        if (e.getProtocol() == Protocol.OIDC && op.getIssuer().equals(e.getIssuer())) {
          staticEntry = e;
          break;
        }
      }
      if (staticEntry == null) {
        entries.add(new IdpDiscoveryInformation(op, IdpDiscoveryInformation.DEFAULT_LANGUAGE));
      }
      else if (!staticEntry.isEnabled()) {
        log.trace("OP '{}' is disabled in configuration and will be excluded from list", op.getIssuer());
      }
      else {
        entries.add(new IdpDiscoveryInformation(op, staticEntry, pos));
      }
    }
    return entries;
  }

  /**
   * Matches the SP entity categories against the IdP to check if the IdP can be used by the SP.
   *
   * @param idp the IdP metadata
   * @return true if the IdP can be used, and false otherwise
   */
  protected boolean isValidIdP(final @NonNull EntityDescriptor idp) {
    final List<String> idpEntityCategories = EntityDescriptorUtils.getEntityCategories(idp);
    if (!SwedishEidDiscoveryMatchingRules.isServiceEntityMatch(this.spEntityCategories, idpEntityCategories)) {
      return false;
    }
    if (!this.ignoreContracts) {
      if (!SwedishEidDiscoveryMatchingRules.isServiceContractMatch(this.spEntityCategories, idpEntityCategories)) {
        return false;
      }
    }
    return SwedishEidDiscoveryMatchingRules.isServicePropertyMatch(this.spEntityCategories, idpEntityCategories);
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
    return System.currentTimeMillis() - this.lastUpdate < this.cacheTime * 1000L;
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
  public static class StaticIdpDiscoEntry implements InitializingBean {

    /**
     * Is the IdP entry enabled?
     */
    private boolean enabled = true;

    /**
     * The protocol of the entry ({@code saml} or {@code oidc}). Defaults to {@code saml}.
     */
    private @NonNull Protocol protocol = Protocol.SAML;

    /**
     * The entity ID for the IdP (for {@code saml} entries).
     */
    private @Nullable String entityId;

    /**
     * The issuer of the OP (for {@code oidc} entries).
     */
    private @Nullable String issuer;

    /**
     * The Swedish display name.
     */
    private @Nullable String displayNameSv;

    /**
     * The Swedish description.
     */
    private @Nullable String descriptionSv;

    /**
     * The English display name.
     */
    private @Nullable String displayNameEn;

    /**
     * The English description.
     */
    private @Nullable String descriptionEn;

    /**
     * The logotype URL.
     */
    private @Nullable String logoUrl;

    /**
     * Logotype width (in pixels).
     */
    private @Nullable Integer logoWidth;

    /**
     * Logotype height (in pixels).
     */
    private @Nullable Integer logoHeight;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.notNull(this.protocol, "protocol for static IdP entry must be 'saml' or 'oidc'");
      if (this.protocol == Protocol.SAML) {
        Assert.hasText(this.entityId, "entity-id for static IdP entry not assigned");
      }
      else {
        Assert.hasText(this.issuer, "issuer for static OP entry not assigned");
      }
    }

    /**
     * Gets the key for the entry: the entity ID for a SAML entry and the issuer for an OIDC entry.
     *
     * @return the key
     */
    public @Nullable String getKey() {
      return this.protocol == Protocol.OIDC ? this.issuer : this.entityId;
    }

    /**
     * Tells whether the IdP entry is enabled.
     *
     * @return {@code true} if the entry is enabled
     */
    public boolean isEnabled() {
      return this.enabled;
    }

    /**
     * Assigns whether the IdP entry is enabled.
     *
     * @param enabled whether the entry is enabled
     */
    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }

    /**
     * Gets the protocol of the entry.
     *
     * @return the protocol of the entry
     */
    public @NonNull Protocol getProtocol() {
      return this.protocol;
    }

    /**
     * Assigns the protocol of the entry ({@code saml} or {@code oidc}).
     *
     * @param protocol the protocol of the entry ({@code saml} or {@code oidc})
     */
    public void setProtocol(final @NonNull Protocol protocol) {
      this.protocol = protocol;
    }

    /**
     * Gets the entity ID for the IdP.
     *
     * @return the entity ID for the IdP
     */
    public @Nullable String getEntityId() {
      return this.entityId;
    }

    /**
     * Assigns the entity ID for the IdP (for {@code saml} entries).
     *
     * @param entityId the entity ID for the IdP (for {@code saml} entries)
     */
    public void setEntityId(final @Nullable String entityId) {
      this.entityId = entityId;
    }

    /**
     * Gets the issuer of the OP.
     *
     * @return the issuer of the OP
     */
    public @Nullable String getIssuer() {
      return this.issuer;
    }

    /**
     * Assigns the issuer of the OP (for {@code oidc} entries).
     *
     * @param issuer the issuer of the OP (for {@code oidc} entries)
     */
    public void setIssuer(final @Nullable String issuer) {
      this.issuer = issuer;
    }

    /**
     * Gets the Swedish display name.
     *
     * @return the Swedish display name
     */
    public @Nullable String getDisplayNameSv() {
      return this.displayNameSv;
    }

    /**
     * Assigns the Swedish display name.
     *
     * @param displayNameSv the Swedish display name
     */
    public void setDisplayNameSv(final @Nullable String displayNameSv) {
      this.displayNameSv = displayNameSv;
    }

    /**
     * Gets the Swedish description.
     *
     * @return the Swedish description
     */
    public @Nullable String getDescriptionSv() {
      return this.descriptionSv;
    }

    /**
     * Assigns the Swedish description.
     *
     * @param descriptionSv the Swedish description
     */
    public void setDescriptionSv(final @Nullable String descriptionSv) {
      this.descriptionSv = descriptionSv;
    }

    /**
     * Gets the English display name.
     *
     * @return the English display name
     */
    public @Nullable String getDisplayNameEn() {
      return this.displayNameEn;
    }

    /**
     * Assigns the English display name.
     *
     * @param displayNameEn the English display name
     */
    public void setDisplayNameEn(final @Nullable String displayNameEn) {
      this.displayNameEn = displayNameEn;
    }

    /**
     * Gets the English description.
     *
     * @return the English description
     */
    public @Nullable String getDescriptionEn() {
      return this.descriptionEn;
    }

    /**
     * Assigns the English description.
     *
     * @param descriptionEn the English description
     */
    public void setDescriptionEn(final @Nullable String descriptionEn) {
      this.descriptionEn = descriptionEn;
    }

    /**
     * Gets the logotype URL.
     *
     * @return the logotype URL
     */
    public @Nullable String getLogoUrl() {
      return this.logoUrl;
    }

    /**
     * Assigns the logotype URL.
     *
     * @param logoUrl the logotype URL
     */
    public void setLogoUrl(final @Nullable String logoUrl) {
      this.logoUrl = logoUrl;
    }

    /**
     * Gets the logo width.
     *
     * @return the logo width
     */
    public @Nullable Integer getLogoWidth() {
      return this.logoWidth;
    }

    /**
     * Assigns the logo width.
     *
     * @param logoWidth the logo width
     */
    public void setLogoWidth(final @Nullable Integer logoWidth) {
      this.logoWidth = logoWidth;
    }

    /**
     * Gets the logo height.
     *
     * @return the logo height
     */
    public @Nullable Integer getLogoHeight() {
      return this.logoHeight;
    }

    /**
     * Assigns the logo height.
     *
     * @param logoHeight the logo height
     */
    public void setLogoHeight(final @Nullable Integer logoHeight) {
      this.logoHeight = logoHeight;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
      return "IdpList.StaticIdpDiscoEntry(enabled=" + this.enabled
          + ", protocol=" + this.protocol
          + ", entityId=" + this.entityId
          + ", issuer=" + this.issuer
          + ", displayNameSv=" + this.displayNameSv
          + ", descriptionSv=" + this.descriptionSv
          + ", displayNameEn=" + this.displayNameEn
          + ", descriptionEn=" + this.descriptionEn
          + ", logoUrl=" + this.logoUrl
          + ", logoWidth=" + this.logoWidth
          + ", logoHeight=" + this.logoHeight
          + ")";
    }

  }

}
