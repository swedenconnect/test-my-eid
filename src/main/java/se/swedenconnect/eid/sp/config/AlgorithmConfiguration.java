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
package se.swedenconnect.eid.sp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import lombok.Data;

/**
 * Configuration class for algorithm support.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Configuration
@ConfigurationProperties(prefix = "sp.security.algorithm-config")
@Data
public class AlgorithmConfiguration {

  /** Which digest method to use for RSA-OAEP. If {@code null}, the default will be used. */
  private String rsaOaepDigest;

  /**
   * Should AES GCM algorithms be used? If {@code false}, AES-CBC will be used as default. If {@code null}, the default
   * will used.
   */
  private Boolean useAesGcm;

  /** Should RSA 1.5 be blacklisted? If {@code null}, RSA 1.5 is allowed. */
  private Boolean blacklistRsa15;

  /**
   * Predicate that tells whether any configuration has been set or not.
   *
   * @return true if no attributes have been configured
   */
  public boolean isEmpty() {
    return !StringUtils.hasText(this.rsaOaepDigest) && this.useAesGcm == null && this.blacklistRsa15 == null;
  }

}
