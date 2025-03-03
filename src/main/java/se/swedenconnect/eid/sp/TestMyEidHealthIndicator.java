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
package se.swedenconnect.eid.sp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;

/**
 * Health indicator for the application.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Component
@Slf4j
public class TestMyEidHealthIndicator implements HealthIndicator {

  /** The federation metadata provider. */
  @Autowired
  private MetadataProvider metadataProvider;

  /**
   * The health implementation for the application.
   */
  @Override
  public Health health() {

    // Assert that we have at least one IdP ...
    //
    try {
      if (this.metadataProvider.getIdentityProviders().isEmpty()) {
        final String msg = "No IdP:s available in metadata";
        log.error("Health check: {}", msg);
        return Health.outOfService().withDetail("error-message", msg).build();
      }
    }
    catch (final ResolverException e) {
      final String msg = "Exception while asking for IdP:s from metadata provider";
      log.error("Health check: {}", msg, e);
      return Health.outOfService().withDetail("error-message", msg).withException(e).build();
    }

    log.debug("Health check: Application status is UP");
    return Health.up().build();
  }

}
