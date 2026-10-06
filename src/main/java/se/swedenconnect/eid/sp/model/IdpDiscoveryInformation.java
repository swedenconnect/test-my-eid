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
package se.swedenconnect.eid.sp.model;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;

import se.swedenconnect.eid.sp.oidc.OpenIdProvider;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;

/**
 * Model object representing info elements of an IdP for display in the UI.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class IdpDiscoveryInformation {

  /** The default languange to use if no match is found. */
  public static final @NonNull String DEFAULT_LANGUAGE = "sv";

  /** The entityID for the IdP. */
  private final @NonNull String entityID;

  /** A map holding display names for different languages, where the language tag is the key. */
  private final Map<String, String> displayNames;

  /** A map holding IdP description strings for different languages, where the language tag is the key. */
  private final Map<String, String> descriptions;

  /** The IdP logotype. */
  private String logotype;

  /** Sorting order for the IdP:s place in the list. */
  private @NonNull Integer sortOrder;

  /** The protocol (SAML for an IdP, OIDC for an OP). */
  private final @NonNull Protocol protocol;

  /** Whether the entry is statically configured. */
  private boolean staticEntry;

  /**
   * Constructor.
   *
   * @param metadata the IdP metadata
   */
  public IdpDiscoveryInformation(final @NonNull EntityDescriptor metadata) {
    this.entityID = metadata.getEntityID();
    this.sortOrder = Integer.MAX_VALUE;
    this.protocol = Protocol.SAML;

    this.displayNames = new HashMap<>();
    this.descriptions = new HashMap<>();

    final UIInfo uiInfo = this.getUIInfo(metadata);
    if (uiInfo != null) {
      uiInfo.getDisplayNames().forEach(d -> this.displayNames.put(d.getXMLLang(), d.getValue()));

      // Prefer a square logo, and if not found, the one that is nearest a square.
      Logo selected = null;
      double widthHeightFactor = Double.MAX_VALUE;
      for (final Logo logo : uiInfo.getLogos()) {
        if (selected == null) {
          selected = logo;
          widthHeightFactor = this.getWidthHeightFactor(logo);
        }
        else {
          final double factor = this.getWidthHeightFactor(logo);
          if (factor == 1) {
            selected = logo;
            break;
          }
          else {
            if (factor < widthHeightFactor) {
              selected = logo;
              widthHeightFactor = factor;
            }
          }
        }
      }
      this.logotype = selected != null ? selected.getURI() : null;
    }
  }

  /**
   * Constructor for a static entry.
   *
   * @param metadata the IdP metadata
   * @param staticEntry the static entry
   * @param sortOrder the sort order
   */
  public IdpDiscoveryInformation(
      final @NonNull EntityDescriptor metadata,
      final @NonNull StaticIdpDiscoEntry staticEntry,
      final int sortOrder) {

    this(metadata);
    this.applyStaticEntry(staticEntry, sortOrder);
  }

  /**
   * Constructor for an OpenID Provider. The name, description and logotype are taken from the OP metadata, and the
   * issuer is used as the name when the metadata holds no name.
   *
   * @param op the OpenID Provider
   * @param language the default language for the logotype
   */
  public IdpDiscoveryInformation(final @NonNull OpenIdProvider op, final @NonNull String language) {
    this.entityID = op.getIssuer();
    this.sortOrder = Integer.MAX_VALUE;
    this.protocol = Protocol.OIDC;
    this.displayNames = new HashMap<>(op.getDisplayNames());
    if (this.displayNames.isEmpty()) {
      this.displayNames.put("", op.getIssuer());
    }
    this.descriptions = new HashMap<>(op.getDescriptions());
    this.logotype = op.getLogo(language);
  }

  /**
   * Constructor for a statically configured OpenID Provider.
   *
   * @param op the OpenID Provider
   * @param staticEntry the static entry
   * @param sortOrder the sort order
   */
  public IdpDiscoveryInformation(final @NonNull OpenIdProvider op, final @NonNull StaticIdpDiscoEntry staticEntry,
      final int sortOrder) {
    this(op, DEFAULT_LANGUAGE);
    this.applyStaticEntry(staticEntry, sortOrder);
  }

  /**
   * Applies the settings of a static entry.
   *
   * @param staticEntry the static entry
   * @param sortOrder the sort order
   */
  private void applyStaticEntry(final @NonNull StaticIdpDiscoEntry staticEntry, final int sortOrder) {
    this.sortOrder = sortOrder;
    this.staticEntry = true;

    Optional.ofNullable(staticEntry.getDisplayNameSv()).ifPresent(d -> this.displayNames.put("sv", d));
    Optional.ofNullable(staticEntry.getDisplayNameEn()).ifPresent(d -> this.displayNames.put("en", d));
    Optional.ofNullable(staticEntry.getDescriptionSv()).ifPresent(d -> this.descriptions.put("sv", d));
    Optional.ofNullable(staticEntry.getDescriptionEn()).ifPresent(d -> this.descriptions.put("en", d));
    Optional.ofNullable(staticEntry.getLogoUrl()).ifPresent(logo -> this.logotype = logo);
  }

  /**
   * Returns the UIInfo extension from the IdP metadata.
   *
   * @param idp the IdP metadata
   * @return the UIInfo extension
   */
  private UIInfo getUIInfo(final EntityDescriptor idp) {
    final SSODescriptor ssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (ssoDescriptor == null) {
      return null;
    }
    return EntityDescriptorUtils.getMetadataExtension(ssoDescriptor.getExtensions(), UIInfo.class);
  }

  /**
   * Returns an IdP list for the given locale.
   *
   * @param locale the locale (language)
   * @return the IdP list
   */
  public @NonNull IdpModel getIdpModel(final @NonNull Locale locale) {
    final IdpModel idp = new IdpModel();
    idp.setEntityID(this.entityID);
    idp.setLogotype(this.logotype);
    String dn = this.displayNames.get(locale.getLanguage());
    if (dn == null) {
      dn = this.displayNames.get(DEFAULT_LANGUAGE);
    }
    if (dn == null) {
      dn = this.displayNames.get("");
    }
    if (dn == null && !this.displayNames.isEmpty()) {
      dn = this.displayNames.values().iterator().next();
    }
    idp.setDisplayName(dn);
    String description = this.descriptions.get(locale.getLanguage());
    if (description == null && this.protocol == Protocol.OIDC) {
      description = this.descriptions.get("");
    }
    idp.setDescription(description);
    idp.setProtocol(this.protocol);
    return idp;
  }

  /**
   * Calculates width - height factor.
   *
   * @param logo the logotype
   * @return width - height factor
   */
  private double getWidthHeightFactor(final Logo logo) {
    if (logo.getWidth() == null || logo.getHeight() == null) {
      return 0;
    }
    return logo.getWidth() >= logo.getHeight()
        ? (double) logo.getWidth() / (double) logo.getHeight()
        : (double) logo.getHeight() / (double) logo.getWidth();
  }

  /**
   * Model for representing selectable IdP:s in the discovery view.
   */
  public static class IdpModel {

    /** The IdP entityID. */
    private @Nullable String entityID;

    /** The IdP display name. */
    private @Nullable String displayName;

    /** The IdP description. */
    private @Nullable String description;

    /** The IdP logotype. */
    private @Nullable String logotype;

    /** The protocol. */
    private @Nullable Protocol protocol;

    /** Whether the logotype should be displayed on a dark background. */
    private boolean darkLogotypeBackground;

    /**
     * Tells whether this is an OpenID Provider.
     *
     * @return {@code true} for an OpenID Provider
     */
    public boolean isOidc() {
      return this.protocol == Protocol.OIDC;
    }

    /**
     * Gets the IdP entityID.
     *
     * @return the IdP entityID
     */
    public @Nullable String getEntityID() {
      return this.entityID;
    }

    /**
     * Assigns the IdP entityID.
     *
     * @param entityID the IdP entityID
     */
    public void setEntityID(final @Nullable String entityID) {
      this.entityID = entityID;
    }

    /**
     * Gets the IdP display name.
     *
     * @return the IdP display name
     */
    public @Nullable String getDisplayName() {
      return this.displayName;
    }

    /**
     * Assigns the IdP display name.
     *
     * @param displayName the IdP display name
     */
    public void setDisplayName(final @Nullable String displayName) {
      this.displayName = displayName;
    }

    /**
     * Gets the IdP description.
     *
     * @return the IdP description
     */
    public @Nullable String getDescription() {
      return this.description;
    }

    /**
     * Assigns the IdP description.
     *
     * @param description the IdP description
     */
    public void setDescription(final @Nullable String description) {
      this.description = description;
    }

    /**
     * Gets the IdP logotype.
     *
     * @return the IdP logotype
     */
    public @Nullable String getLogotype() {
      return this.logotype;
    }

    /**
     * Assigns the IdP logotype.
     *
     * @param logotype the IdP logotype
     */
    public void setLogotype(final @Nullable String logotype) {
      this.logotype = logotype;
    }

    /**
     * Gets the protocol.
     *
     * @return the protocol
     */
    public @Nullable Protocol getProtocol() {
      return this.protocol;
    }

    /**
     * Assigns the protocol.
     *
     * @param protocol the protocol
     */
    public void setProtocol(final @Nullable Protocol protocol) {
      this.protocol = protocol;
    }

    /**
     * Tells whether the logotype should be displayed on a dark background.
     *
     * @return {@code true} if the logotype should be displayed on a dark background
     */
    public boolean isDarkLogotypeBackground() {
      return this.darkLogotypeBackground;
    }

    /**
     * Assigns whether the logotype should be displayed on a dark background.
     *
     * @param darkLogotypeBackground whether the logotype should be displayed on a dark background
     */
    public void setDarkLogotypeBackground(final boolean darkLogotypeBackground) {
      this.darkLogotypeBackground = darkLogotypeBackground;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
      return "IdpDiscoveryInformation.IdpModel(entityID=" + this.entityID
          + ", displayName=" + this.displayName
          + ", description=" + this.description
          + ", logotype=" + this.logotype
          + ", protocol=" + this.protocol
          + ", darkLogotypeBackground=" + this.darkLogotypeBackground
          + ")";
    }
  }

  /**
   * Gets the entityID for the IdP.
   *
   * @return the entityID for the IdP
   */
  public @NonNull String getEntityID() {
    return this.entityID;
  }

  /**
   * Gets the sorting order for the IdP:s place in the list.
   *
   * @return the sort order
   */
  public @NonNull Integer getSortOrder() {
    return this.sortOrder;
  }

  /**
   * Gets the protocol (SAML for an IdP, OIDC for an OP).
   *
   * @return the protocol (SAML for an IdP, OIDC for an OP)
   */
  public @NonNull Protocol getProtocol() {
    return this.protocol;
  }

  /**
   * Tells whether the entry is statically configured.
   *
   * @return {@code true} if the entry is statically configured
   */
  public boolean isStaticEntry() {
    return this.staticEntry;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "IdpDiscoveryInformation(entityID=" + this.entityID
        + ", displayNames=" + this.displayNames
        + ", descriptions=" + this.descriptions
        + ", logotype=" + this.logotype
        + ", sortOrder=" + this.sortOrder
        + ", protocol=" + this.protocol
        + ", staticEntry=" + this.staticEntry
        + ")";
  }

}
