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
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

/**
 * Configuration class for security support.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Configuration
@ConfigurationProperties("sp.security")
public class AlgorithmConfiguration {

  /**
   * Custom algorithm configuration.
   */
  private @Nullable CustomAlgorithms algorithmConfig;

  /**
   * Gets the custom algorithm configuration.
   *
   * @return the custom algorithm configuration
   */
  public @Nullable CustomAlgorithms getAlgorithmConfig() {
    return this.algorithmConfig;
  }

  /**
   * Assigns the custom algorithm configuration.
   *
   * @param algorithmConfig the custom algorithm configuration
   */
  public void setAlgorithmConfig(final @Nullable CustomAlgorithms algorithmConfig) {
    this.algorithmConfig = algorithmConfig;
  }

  /**
   * Gets the algorithm configuration bean.
   *
   * @return an {@link CustomAlgorithms} bean
   */
  @Bean
  @NonNull CustomAlgorithms customAlgorithms() {
    return this.algorithmConfig != null ? this.algorithmConfig : new CustomAlgorithms();
  }

  /**
   * Algorithm configuration
   *
   * @author Martin Lindström
   */
  public static class CustomAlgorithms {

    /**
     * Which digest method to use for RSA-OAEP. If {@code null}, the default will be used.
     */
    private @Nullable String rsaOaepDigest;

    /**
     * Should AES GCM algorithms be used? If {@code false}, AES-CBC will be used as default. If {@code null}, the
     * default will be used.
     */
    private @Nullable Boolean useAesGcm;

    /**
     * Should RSA 1.5 be blacklisted?
     */
    private @Nullable Boolean blacklistRsa15;

    /**
     * Gets which digest method to use for RSA-OAEP.
     *
     * @return the digest method, or {@code null} for the default
     */
    public @Nullable String getRsaOaepDigest() {
      return this.rsaOaepDigest;
    }

    /**
     * Assigns which digest method to use for RSA-OAEP.
     *
     * @param rsaOaepDigest the digest method, or {@code null} for the default
     */
    public void setRsaOaepDigest(final @Nullable String rsaOaepDigest) {
      this.rsaOaepDigest = rsaOaepDigest;
    }

    /**
     * Gets whether AES GCM algorithms should be used.
     *
     * @return whether AES GCM should be used, or {@code null} for the default
     */
    public @Nullable Boolean getUseAesGcm() {
      return this.useAesGcm;
    }

    /**
     * Assigns whether AES GCM algorithms should be used.
     *
     * @param useAesGcm whether AES GCM should be used, or {@code null} for the default
     */
    public void setUseAesGcm(final @Nullable Boolean useAesGcm) {
      this.useAesGcm = useAesGcm;
    }

    /**
     * Gets whether RSA 1.5 should be blacklisted.
     *
     * @return whether RSA 1.5 should be blacklisted, or {@code null} for the default
     */
    public @Nullable Boolean getBlacklistRsa15() {
      return this.blacklistRsa15;
    }

    /**
     * Assigns whether RSA 1.5 should be blacklisted.
     *
     * @param blacklistRsa15 whether RSA 1.5 should be blacklisted, or {@code null} for the default
     */
    public void setBlacklistRsa15(final @Nullable Boolean blacklistRsa15) {
      this.blacklistRsa15 = blacklistRsa15;
    }

    /**
     * Predicate that tells whether any configuration has been set or not.
     *
     * @return true if no attributes have been configured
     */
    public boolean isEmpty() {
      return !StringUtils.hasText(this.getRsaOaepDigest())
          && this.getUseAesGcm() == null
          && this.getBlacklistRsa15() == null;
    }

  }

}
