/*
 * Copyright 2018-2024 Sweden Connect
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
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.Organization;
import org.springframework.util.StringUtils;

import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration.ContactPersonConfig;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration.OrganizationConfig;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration.RequestedAttributeConfig;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration.UIInfoConfig;
import se.swedenconnect.eid.sp.config.SpConfigurationProperties.MetadataConfiguration.UIInfoConfig.UIInfoLogo;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;

/**
 * Utility methods for working with SAML metadata.
 *
 * @author Martin Lindström
 */
public class MetadataUtils {

  public static UIInfo getUIInfoElement(final UIInfoConfig uiinfo, final String baseUri, final String contextPath) {
    if (uiinfo == null) {
      return null;
    }
    return UIInfoBuilder.builder()
        .displayNames(uiinfo.getDisplayNames())
        .descriptions(uiinfo.getDescriptions())
        .logos(getUiInfoLogos(uiinfo.getLogos(), baseUri, contextPath))
        .build();
  }

  private static List<Logo> getUiInfoLogos(final List<UIInfoLogo> logos, final String baseUri,
      final String contextPath) {
    if (logos == null) {
      return Collections.emptyList();
    }
    final String _contextPath = "/".equals(contextPath) ? "" : contextPath;
    return logos.stream()
        .map(l -> LogoBuilder.logo(String.format("%s%s%s", baseUri, _contextPath, l.getPath()), l.getHeight(),
            l.getWidth()))
        .collect(Collectors.toList());
  }

  public static Organization getOrganizationElement(final OrganizationConfig organization) {
    if (organization == null) {
      return null;
    }
    return OrganizationBuilder.builder()
        .organizationNames(organization.getNames())
        .organizationDisplayNames(organization.getDisplayNames())
        .organizationURLs(organization.getUrls())
        .build();
  }

  public static List<ContactPerson> getContactPersonElements(
      final Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons) {
    if (contactPersons == null || contactPersons.isEmpty()) {
      return Collections.emptyList();
    }
    final List<ContactPerson> persons = new ArrayList<>();
    for (final Map.Entry<ContactPersonTypeEnumeration, ContactPersonConfig> e : contactPersons.entrySet()) {
      final ContactPersonBuilder b = ContactPersonBuilder.builder()
          .type(e.getKey())
          .company(e.getValue().getCompany())
          .givenName(e.getValue().getGivenName())
          .surname(e.getValue().getSurname());
      if (StringUtils.hasText(e.getValue().getEmailAddress())) {
        b.emailAddresses(e.getValue().getEmailAddress());
      }
      if (StringUtils.hasText(e.getValue().getTelephoneNumber())) {
        b.telephoneNumbers(e.getValue().getTelephoneNumber());
      }
      persons.add(b.build());
    }
    return persons;
  }

  public static AttributeConsumingService getAttributeConsumingService(
      final List<LocalizedString> serviceNames, final List<RequestedAttributeConfig> requestedAttributes) {
    if ((serviceNames == null || serviceNames.isEmpty())
        && (requestedAttributes == null || requestedAttributes.isEmpty())) {
      return null;
    }
    final AttributeConsumingServiceBuilder builder = AttributeConsumingServiceBuilder.builder();

    builder.serviceNames(serviceNames);

    if (requestedAttributes != null) {
      builder.requestedAttributes(requestedAttributes.stream()
          .filter(ra -> ra.getName() != null)
          .map(ra -> RequestedAttributeBuilder.builder(ra.getName()).isRequired(ra.isRequired()).build())
          .collect(Collectors.toList()));
    }

    return builder.build();
  }

  private MetadataUtils() {
  }

}
