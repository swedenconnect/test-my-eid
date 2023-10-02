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
package se.swedenconnect.eid.sp.saml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.opensaml.xmlsec.DecryptionConfiguration;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.impl.BasicDecryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.eid.sp.config.AlgorithmConfiguration;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/**
 * Security configuration class for initialization of algorithm support.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Slf4j
public class CustomSwedishEidSecurityConfiguration extends SwedishEidSecurityConfiguration {

  /** Customized algorithm configuration. */
  private AlgorithmConfiguration algorithmConfiguration;

  /**
   * Constructor assigning the customized algorithm configuration.
   *
   * @param algorithmConfiguration customized algorithm configuration
   */
  public CustomSwedishEidSecurityConfiguration(final AlgorithmConfiguration algorithmConfiguration) {
    this.algorithmConfiguration = algorithmConfiguration;
  }

  /** {@inheritDoc} */
  @Override
  public String getProfileName() {
    return this.algorithmConfiguration.isEmpty() ? super.getProfileName() : "custom-swedish-eid-framework";
  }

  /**
   * Adds customized algorithm settings.
   */
  @Override
  protected EncryptionConfiguration createDefaultEncryptionConfiguration() {
    BasicEncryptionConfiguration config = (BasicEncryptionConfiguration) super.createDefaultEncryptionConfiguration();

    if (StringUtils.hasText(this.algorithmConfiguration.getRsaOaepDigest())) {
      log.debug("Using digest method '{}' for RSA-OAEP", this.algorithmConfiguration.getRsaOaepDigest());
      RSAOAEPParameters pars = config.getRSAOAEPParameters();

      config.setRSAOAEPParameters(new RSAOAEPParameters(
          this.algorithmConfiguration.getRsaOaepDigest(),
          pars != null ? pars.getMaskGenerationFunction() : EncryptionConstants.ALGO_ID_MGF1_SHA1,
          pars != null ? pars.getOAEPParams() : null));
    }

    if (this.algorithmConfiguration.getUseAesGcm() != null) {
      // We could fix this prettier ...
      if (this.algorithmConfiguration.getUseAesGcm().booleanValue()) {
        log.debug("Setting AES-GCM as default block cipher");
        config.setDataEncryptionAlgorithms(Arrays.asList(
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES));
      }
      else {
        log.debug("Setting AES-CBC as default block cipher");
        config.setDataEncryptionAlgorithms(Arrays.asList(
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES));
      }
    }

    return config;
  }

  /**
   * Adds customized algorithm settings.
   */
  @Override
  protected DecryptionConfiguration createDefaultDecryptionConfiguration() {
    if (this.algorithmConfiguration.getBlacklistRsa15() != null) {
      BasicDecryptionConfiguration config = (BasicDecryptionConfiguration) super.createDefaultDecryptionConfiguration();
      if (config == null) {
        config = DefaultSecurityConfigurationBootstrap.buildDefaultDecryptionConfiguration();
      }

      Predicate<String> isNotRsa15 = alg -> !EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15.equals(alg);

      if (this.algorithmConfiguration.getBlacklistRsa15().booleanValue()) {
        config.setIncludedAlgorithms(config.getIncludedAlgorithms().stream()
            .filter(isNotRsa15)
            .collect(Collectors.toList()));

        if (!config.getExcludedAlgorithms().contains(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15)) {
          List<String> bl = new ArrayList<>(config.getExcludedAlgorithms());
          bl.add(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
          config.setExcludedAlgorithms(bl);
        }
      }
      else {
        config.setExcludedAlgorithms(config.getExcludedAlgorithms().stream()
            .filter(isNotRsa15)
            .collect(Collectors.toList()));
      }
      return config;
    }
    else {
      return super.createDefaultDecryptionConfiguration();
    }
  }

}
