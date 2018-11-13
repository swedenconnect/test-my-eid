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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.Organization;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import lombok.Data;
import se.litsec.opensaml.core.LocalizedString;
import se.litsec.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.litsec.opensaml.saml2.metadata.build.LogoBuilder;
import se.litsec.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.litsec.opensaml.saml2.metadata.build.UIInfoBuilder;

/**
 * Configuration class for SP metadata.
 * 
 * @author Martin Lindström (martin@litsec.se)
 */
@Configuration
@ConfigurationProperties(prefix = "sp.metadata")
@DependsOn("openSAML")
@Data
public class MetadataConfiguration {

  /** The entity categories to include in the metadata extension. */
  List<String> entityCategories;

  /** Configuration for the UIInfo extension. */
  UIInfoConfig uiinfo;

  /** Configuration for the Organization element. */
  OrganizationConfig organization;

  /** Configuration for the ContactPerson elements. */
  Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons;
  
  /**
   * Returns a list of the entity category URI:s
   * 
   * @return the entity categories
   */
  public List<String> getEntityCategories() {
    return this.entityCategories;
  }

  /**
   * Returns a {@link UIInfo} element
   * 
   * @return the {@link UIInfo}
   */
  public UIInfo getUIInfoElement(String baseUri, String contextPath) {
    return UIInfoBuilder.builder()
      .displayNames(this.uiinfo.getDisplayNames())
      .descriptions(this.uiinfo.getDescriptions())
      .logos(this.uiinfo.getUiInfoLogos(baseUri, contextPath))
      .build();
  }

  /**
   * Returns the {@link Organization} element
   * 
   * @return the {@link Organization}
   */
  public Organization getOrganizationElement() {
    return OrganizationBuilder.builder()
      .organizationNames(this.organization.getNames())
      .organizationDisplayNames(this.organization.getDisplayNames())
      .organizationURLs(this.organization.getUrls())
      .build();
  }

  /**
   * Returns a list of {@link ContactPerson} elements.
   * 
   * @return a list of {@link ContactPerson} elements
   */
  public List<ContactPerson> getContactPersonElements() {
    if (this.contactPersons == null || this.contactPersons.isEmpty()) {
      return Collections.emptyList();
    }
    List<ContactPerson> persons = new ArrayList<>();
    for (Map.Entry<ContactPersonTypeEnumeration, ContactPersonConfig> e : this.contactPersons.entrySet()) {
      persons.add(ContactPersonBuilder.builder()
        .type(e.getKey())
        .company(e.getValue().getCompany())
        .givenName(e.getValue().getGivenName())
        .surname(e.getValue().getSurname())
        .emailAddresses(e.getValue().getEmailAddress())
        .telephoneNumbers(e.getValue().getTelephoneNumber())
        .build());
    }
    return persons;
  }

  /**
   * Configuration class for UIInfo.
   */
  @Data
  public static class UIInfoConfig {
    /** The UIInfo display names. Given as <country-code>-<text>. */
    private List<LocalizedString> displayNames;

    /** The UIInfo descriptions. Given as <country-code>-<text>. */
    private List<LocalizedString> descriptions;

    /** The UIInfo logotypes */
    private List<UIInfoLogo> logos;

    public List<Logo> getUiInfoLogos(String baseUri, String contextPath) {
      if (this.logos == null) {
        return Collections.emptyList();
      }
      final String _contextPath = "/".equals(contextPath) ? "" : contextPath;  
      return this.logos.stream()
        .map(l -> LogoBuilder.logo(String.format("%s%s%s", baseUri, _contextPath, l.getPath()), l.getHeight(), l.getWidth()))
        .collect(Collectors.toList());
    }

    /**
     * Configuration class for the Logo element of the UIInfo element.
     */
    @Data
    public static class UIInfoLogo {
      
      /** The logotype path (minus baseUri and context-path). */
      private String path;
      
      /** The logotype height (in pixels). */
      private Integer height;

      /** The logotype width (in pixels). */
      private Integer width;
    }
  }

  /**
   * Configuration class for the Organization element.
   */
  @Data
  public static class OrganizationConfig {
    /** The organization names. Given as <country-code>-<text>. */
    private List<LocalizedString> names;

    /** The organization display names. Given as <country-code>-<text>. */
    private List<LocalizedString> displayNames;

    /** The organization URL:s. */
    private List<LocalizedString> urls;
  }

  /**
   * Configuration class for the ContactPerson element.
   */
  @Data
  public static class ContactPersonConfig {
    /** The company. */
    private String company;

    /** Given name. */
    private String givenName;

    /** Surname. */
    private String surname;

    /** Email address. */
    private String emailAddress;

    /** Telephone number. */
    private String telephoneNumber;
  }

}
