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
package se.swedenconnect.eid.sp.oidc;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.eid.sp.config.RpConfigurationProperties;

import java.util.List;

/**
 * Checks the {@code acr} issued by an OP found through the OpenID Federation against the OP's Level of Assurance trust
 * marks.
 *
 * @author Martin Lindström
 */
public class LoaTrustMarkChecker {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(LoaTrustMarkChecker.class);

  /** The rules mapping {@code acr} values to required trust marks. */
  private final @NonNull List<RpConfigurationProperties.LoaTrustMarkRule> rules;

  /**
   * Constructor.
   *
   * @param rules the rules mapping {@code acr} values to required trust marks
   */
  public LoaTrustMarkChecker(final @NonNull List<RpConfigurationProperties.LoaTrustMarkRule> rules) {
    this.rules = List.copyOf(rules);
  }

  /**
   * Tells whether the OP has the trust marks that the {@code acr} needs. Always {@code true} for manually configured
   * OPs and for {@code acr} values that need no trust mark.
   *
   * @param op the OP
   * @param acr the {@code acr} from the ID token
   * @return {@code true} if no trust mark is missing
   */
  public boolean hasRequiredTrustMark(final @NonNull OpenIdProvider op, final @Nullable String acr) {
    if (op.getSource() != OpenIdProvider.Source.FEDERATION || acr == null) {
      return true;
    }
    for (final RpConfigurationProperties.LoaTrustMarkRule rule : this.rules) {
      if (rule.getAcr().contains(acr) && !op.getTrustMarkTypes().containsAll(rule.getTrustMarks())) {
        log.info("OP '{}' issued acr '{}' but lacks trust marks {} [has {}]",
            op.getIssuer(), acr, rule.getTrustMarks(), op.getTrustMarkTypes());
        return false;
      }
    }
    return true;
  }

}
