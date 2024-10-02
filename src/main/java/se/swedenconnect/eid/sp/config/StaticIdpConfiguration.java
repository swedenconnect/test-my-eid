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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;

/**
 * Configuration class for reading statically configured IdP:s from the {@code sp.discovery.static-idp-configuration}
 * setting.
 *
 * @author Martin Lindström
 */
@Configuration
@ConfigurationProperties
@PropertySource(ignoreResourceNotFound = true, value = "${sp.discovery.static-idp-configuration}", factory = CustomPropertySourceFactory.class)
public class StaticIdpConfiguration implements InitializingBean {

  /**
   * Statically configured IdP:s.
   */
  @Getter
  @Setter
  private List<StaticIdpDiscoEntry> idp;

  @Bean("staticIdps")
  List<StaticIdpDiscoEntry> staticIdps() {
    return Optional.ofNullable(this.idp).orElseGet(() -> Collections.emptyList());
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.idp != null) {
      for (final StaticIdpDiscoEntry e : this.idp) {
        e.afterPropertiesSet();
      }
    }
  }

}
