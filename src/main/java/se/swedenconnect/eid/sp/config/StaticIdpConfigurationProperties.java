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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import se.swedenconnect.eid.sp.saml.IdpList;

import java.io.Serial;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for statically configured IdP:s.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties(prefix = "idp")
public class StaticIdpConfigurationProperties extends ArrayList<IdpList.StaticIdpDiscoEntry> {

  @Serial
  private static final long serialVersionUID = -4620694286344712583L;

  public List<IdpList.StaticIdpDiscoEntry> getIdp() {
    return this;
  }

}
