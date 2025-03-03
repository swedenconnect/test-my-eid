/*
 * Copyright 2018-2025 Sweden Connect
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

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;

import lombok.Data;
import lombok.Getter;
import lombok.ToString;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;

/**
 * Model object representing info elements of an IdP for display in the UI.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@ToString
public class IdpDiscoveryInformation {

  /** The default languange to use if no match is found. */
  public static final String DEFAULT_LANGUAGE = "sv";

  /** The entityID for the IdP. */
  @Getter
  private final String entityID;

  /** A map holding display names for different languages, where the language tag is the key. */
  private final Map<String, String> displayNames;

  /** A map holding IdP description strings for different languages, where the language tag is the key. */
  private final Map<String, String> descriptions;

  /** The IdP logotype. */
  private String logotype;

  /** Sorting order for the IdP:s place in the list. */
  @Getter
  private Integer sortOrder;

  /**
   * Constructor.
   *
   * @param metadata the IdP metadata
   */
  public IdpDiscoveryInformation(final EntityDescriptor metadata) {
    this.entityID = metadata.getEntityID();
    this.sortOrder = Integer.MAX_VALUE;

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
      final EntityDescriptor metadata,
      final StaticIdpDiscoEntry staticEntry,
      final int sortOrder) {

    this(metadata);
    this.sortOrder = sortOrder;

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
  public IdpModel getIdpModel(final Locale locale) {
    final IdpModel idp = new IdpModel();
    idp.setEntityID(this.entityID);
    idp.setLogotype(this.logotype);
    String dn = this.displayNames.get(locale.getLanguage());
    if (dn == null) {
      dn = this.displayNames.get(DEFAULT_LANGUAGE);
    }
    if (dn == null && !this.displayNames.isEmpty()) {
      dn = this.displayNames.entrySet().iterator().next().getValue();
    }
    idp.setDisplayName(dn);
    idp.setDescription(this.descriptions.get(locale.getLanguage()));
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
  @Data
  @ToString
  public static class IdpModel {

    /** The IdP entityID. */
    private String entityID;

    /** The IdP display name. */
    private String displayName;

    /** The IdP description. */
    private String description;

    /** The IdP logotype. */
    private String logotype;
  }

}
