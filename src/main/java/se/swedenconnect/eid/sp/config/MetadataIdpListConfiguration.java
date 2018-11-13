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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.litsec.opensaml.saml2.metadata.MetadataUtils;
import se.litsec.opensaml.saml2.metadata.provider.MetadataProvider;
import se.litsec.swedisheid.opensaml.saml2.discovery.SwedishEidDiscoveryMatchingRules;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryMetadataHelper;
import se.swedenconnect.eid.sp.config.StaticIdpConfiguration.StaticIdpDiscoEntry;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation;

/**
 * An IdP list configuration that gets its configuration from the supplied metadata provider.
 * 
 * @author Martin Lindström (martin@litsec.se)
 */
@Configuration
@Slf4j
public class MetadataIdpListConfiguration implements IdpListConfiguration {

  /** The default time to keep an IdP list in the cache (10 minutes). */
  public static int DEFAULT_CACHE_TIME = 600;

  /** The metadata provider from where we get the IdP:s. */
  @Autowired
  private MetadataProvider metadataProvider;

  /** The SP entity categories. */
  private List<String> spEntityCategories;

  /** The time we should keep an IdP list in the cache (in seconds). */
  @Value("${sp.discovery.cache-time:600}")
  private int cacheTime = DEFAULT_CACHE_TIME;

  /** Setting that tells whether we should ignore contract entity categories when matching. */
  @Value("${sp.discovery.ignore-contracts:true}")
  private boolean ignoreContracts = true;

  /** Configuration for static conf of IdPs. */
  @Autowired
  private StaticIdpConfiguration staticIdpConfiguration;

  /** The IdP list cache. */
  private List<IdpDiscoveryInformation> cache;

  /** The last time the cache was updated. */
  private long lastUpdate = 0;

  /**
   * Constructor.
   * 
   * @param spMetadata
   *          the metadata for our SP
   */
  public MetadataIdpListConfiguration(@Autowired EntityDescriptor spMetadata) {
    this.spEntityCategories = EntityCategoryMetadataHelper.getEntityCategories(spMetadata);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized List<IdpDiscoveryInformation> getIdps() {
    if (this.validCache()) {
      return this.cache;
    }
    log.debug("Compiling IdP list from metadata {}", this.metadataProvider.getID());

    List<IdpDiscoveryInformation> idpList = new ArrayList<>();

    try {
      List<EntityDescriptor> idps = this.metadataProvider.getIdentityProviders();
      for (EntityDescriptor idp : idps) {
        
        if (this.staticIdpConfiguration.isBlackListed(idp.getEntityID())) {
          log.debug("IdP '{}' is black-listed in configuration and will be excluded from IdP list", idp.getEntityID());
          continue;
        }
        
        StaticIdpDiscoEntry discoInfo = this.staticIdpConfiguration.getIdpDiscoInformation(idp.getEntityID())
            .orElse(this.getDefaultDiscoInformation(idp.getEntityID()));
        
        if (!discoInfo.isEnabled()) {
          log.debug("IdP '{}' is disabled in configuration and will be excluded from IdP list", idp.getEntityID());
          continue;
        }

        if (discoInfo.isSkipEntityCategoryMatching() || this.isValidIdP(idp)) {
          
          UIInfo uiInfo = this.getUIInfo(idp);
          if (uiInfo == null) {
            log.warn("IdP '{}' does not define an UIInfo extension", idp.getEntityID());
            idpList.add(new IdpDiscoveryInformation(idp.getEntityID(), Collections.emptyList(), Collections.emptyList(), discoInfo));
          }
          else {
            idpList.add(new IdpDiscoveryInformation(idp.getEntityID(), uiInfo.getDisplayNames(), uiInfo.getLogos(), discoInfo));
          }
        }
        else {
          log.info("IdP '{}' removed from IdP listing - no matching entity categories", idp.getEntityID());
        }
      }
    }
    catch (ResolverException e) {
      log.error("Error listing metadata", e);
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
   * Returns a {@code IdpDiscoInformation} object to be used when the IdP is not explicitly configured.
   * 
   * @param entityId
   *          the IdP entity
   * @return a default {@code IdpDiscoInformation}
   */
  private StaticIdpDiscoEntry getDefaultDiscoInformation(String entityId) {
    StaticIdpDiscoEntry discoInfo = new StaticIdpDiscoEntry();
    discoInfo.setEntityId(entityId);
    discoInfo.setEnabled(this.staticIdpConfiguration.getIncludeUnlisted());
    return discoInfo;
  }

  /**
   * Matches the SP entity categories against the IdP to check if the IdP can be used by the SP.
   * 
   * @param idp
   *          the IdP metadata
   * @return {@code true} if the IdP can be used, and {@code false} otherwise
   */
  protected boolean isValidIdP(EntityDescriptor idp) {
    final List<String> idpEntityCategories = EntityCategoryMetadataHelper.getEntityCategories(idp);
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
   * Returns the UIInfo extension from the IdP metadata.
   * 
   * @param idp
   *          the IdP metadata
   * @return the UIInfo extension
   */
  private UIInfo getUIInfo(EntityDescriptor idp) {
    SSODescriptor ssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (ssoDescriptor == null) {
      return null;
    }
    return MetadataUtils.getMetadataExtension(ssoDescriptor.getExtensions(), UIInfo.class).orElse(null);
  }

  /**
   * Predicate that checks if the cache is still valid.
   * 
   * @return {@code true} if the cache is still valid and {@code false} otherwise
   */
  private boolean validCache() {
    return (System.currentTimeMillis() - this.lastUpdate > (this.cacheTime * 1000L)) && this.cache != null;
  }

}
