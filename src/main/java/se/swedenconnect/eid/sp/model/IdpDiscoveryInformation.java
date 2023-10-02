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
package se.swedenconnect.eid.sp.model;

import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.Logo;

import lombok.Data;
import lombok.Getter;
import lombok.ToString;
import se.swedenconnect.eid.sp.config.StaticIdpConfiguration.StaticIdpDiscoEntry;

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
  private Integer sortOrder = Integer.MAX_VALUE;

  /** Can the IdP be used from a mobile device? */
  @Getter
  private boolean mobileUse = true;

  /**
   * Constructor setting up an IdP info entry.
   *
   * @param entityID the IdP entityID
   * @param displayNames the display names found in metadata
   * @param logotypes the logotypes found in metadata
   * @param mobileAuth is the {@code http://id.elegnamnden.se/sprop/1.0/mobile-auth} service property category present
   *          in IdP metadata?
   * @param discoInfo statically configured data for the IdP
   */
  public IdpDiscoveryInformation(
      final String entityID, final Collection<DisplayName> displayNames, final Collection<Logo> logotypes,
      final boolean mobileAuth,
      final StaticIdpDiscoEntry discoInfo) {

    this.entityID = entityID;

    this.sortOrder = discoInfo.getSortOrder();

    this.mobileUse = discoInfo.getMobileUse() != null ? discoInfo.getMobileUse().booleanValue() : mobileAuth;

    this.displayNames = new HashMap<>();
    displayNames.stream().forEach(d -> this.displayNames.put(d.getXMLLang(), d.getValue()));

    if (discoInfo.getDisplayNameSv() != null) {
      this.displayNames.put("sv", discoInfo.getDisplayNameSv());
    }
    if (discoInfo.getDisplayNameEn() != null) {
      this.displayNames.put("en", discoInfo.getDisplayNameEn());
    }
    this.descriptions = new HashMap<>();
    if (discoInfo.getDescriptionSv() != null) {
      this.descriptions.put("sv", discoInfo.getDescriptionSv());
    }
    if (discoInfo.getDescriptionEn() != null) {
      this.descriptions.put("en", discoInfo.getDescriptionEn());
    }

    if (discoInfo.getLogoUrl() != null) {
      this.logotype = discoInfo.getLogoUrl();
    }
    else {
      // Prefer a square logo, and if not found, the one that is nearest a square.
      Logo selected = null;
      double widthHeightFactor = Double.MAX_VALUE;
      for (final Logo logo : logotypes) {
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
