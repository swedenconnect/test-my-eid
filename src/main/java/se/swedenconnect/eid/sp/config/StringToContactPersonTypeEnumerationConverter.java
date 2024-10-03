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

import jakarta.annotation.Nonnull;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

/**
 * Converts from a String to a {@link ContactPersonTypeEnumeration}.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Component
@ConfigurationPropertiesBinding
public class StringToContactPersonTypeEnumerationConverter implements Converter<String, ContactPersonTypeEnumeration> {

  /** {@inheritDoc} */
  @Override
  public ContactPersonTypeEnumeration convert(@Nonnull final String source) {
    if (ContactPersonTypeEnumeration.SUPPORT.toString().equalsIgnoreCase(source)) {
      return ContactPersonTypeEnumeration.SUPPORT;
    }
    else if (ContactPersonTypeEnumeration.TECHNICAL.toString().equalsIgnoreCase(source)) {
      return ContactPersonTypeEnumeration.TECHNICAL;
    }
    else if (ContactPersonTypeEnumeration.ADMINISTRATIVE.toString().equalsIgnoreCase(source)) {
      return ContactPersonTypeEnumeration.ADMINISTRATIVE;
    }
    else if (ContactPersonTypeEnumeration.BILLING.toString().equalsIgnoreCase(source)) {
      return ContactPersonTypeEnumeration.BILLING;
    }
    else if (ContactPersonTypeEnumeration.OTHER.toString().equalsIgnoreCase(source)) {
      return ContactPersonTypeEnumeration.OTHER;
    }
    else {
      return null;
    }
  }

}
