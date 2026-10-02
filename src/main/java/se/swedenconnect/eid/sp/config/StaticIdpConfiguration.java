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
package se.swedenconnect.eid.sp.config;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.PropertySource;
import se.swedenconnect.eid.sp.saml.IdpList.StaticIdpDiscoEntry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Configuration class for reading statically configured IdP:s from the {@code sp.discovery.static-idp-configuration}
 * setting.
 *
 * @author Martin Lindström
 */
@Configuration
@PropertySource(ignoreResourceNotFound = true, value = "${sp.discovery.static-idp-configuration}", factory = CustomPropertySourceFactory.class)
@EnableConfigurationProperties(StaticIdpConfigurationProperties.class)
public class StaticIdpConfiguration {

  private final StaticIdpConfigurationProperties props;

  /**
   * Constructor.
   *
   * @param props the static IdP configuration properties
   */
  public StaticIdpConfiguration(final @NonNull StaticIdpConfigurationProperties props) {
    this.props = props;
  }

  /**
   * Returns the statically configured IdP:s.
   *
   * @return a list of IdP entries (may be empty)
   */
  @Bean("staticIdps")
  @NonNull List<StaticIdpDiscoEntry> staticIdps() {
    final List<StaticIdpDiscoEntry> idps = Optional.ofNullable(this.props.getIdp()).orElse(Collections.emptyList());
    for (final StaticIdpDiscoEntry entry : idps) {
      entry.afterPropertiesSet();
    }
    return idps;
  }

}
