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
package se.swedenconnect.eid.sp.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import se.swedenconnect.eid.sp.saml.TestMyEidAuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;

/**
 * Assigns the texts describing a Level of Assurance URI to an {@link AuthenticationInfo}. Used for both SAML
 * ({@code AuthnContextClassRef}) and OpenID Connect ({@code acr}), since they use the same URIs.
 *
 * @author Martin Lindström
 */
public final class LoaMessages {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(LoaMessages.class);

  // Hidden constructor
  private LoaMessages() {
  }

  /**
   * Assigns the LoA URI and its texts to the authentication info.
   *
   * @param info the authentication info to update
   * @param loa the LoA URI
   * @return {@code true} if the LoA is an eIDAS LoA
   */
  public static boolean apply(final @NonNull AuthenticationInfo info, final @Nullable String loa) {
    boolean isEidas = false;

    info.setLoaUri(loa);

    if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage".equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa3");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA3.equals(loa) ||
        "http://id.swedenconnect.se/loa/1.0/uncertified-loa3-sigmessage".equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa3-uncertified");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3_NONRESIDENT.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa3-nonresident");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage".equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa2");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_LOA2.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa2-uncertified");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2_NONRESIDENT.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa2-nonresident");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4.equals(loa) ||
        "http://id.elegnamnden.se/loa/1.0/loa4-sigmessage".equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa4");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA4_NONRESIDENT.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa4-nonresident");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa.desc");
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-low-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_LOW.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa-low");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      info.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)) {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_LOW.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-low-sigm".equals(loa)) {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-sub-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_SUBSTANTIAL.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa-substantial");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      info.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)) {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_SUBSTANTIAL.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm".equals(loa)) {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH.equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH_NF.equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-high-sigm".equals(loa)
        || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)
        || LevelOfAssuranceUris.AUTHN_CONTEXT_URI_UNCERTIFIED_EIDAS_HIGH.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-according-loa-high");
      info.setLoaLevelDescriptionCode("sp.msg.authn-according-loa-eidas.desc");
      info.setEidasAssertion(true);
      isEidas = true;

      if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH_NF.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)) {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-notified");
      }
      else if (LevelOfAssuranceUris.AUTHN_CONTEXT_URI_EIDAS_HIGH.equals(loa)
          || "http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm".equals(loa)) {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-non-notified");
      }
      else {
        info.setNotifiedInfoMessageCode("sp.msg.authn-according-uncertified-eidas");
      }
    }
    else if (TestMyEidAuthnRequestGeneratorContext.EIDAS_PING_LOA.equals(loa)) {
      info.setLoaLevelMessageCode("sp.msg.authn-eidas-test");
      info.setLoaLevelDescriptionCode("sp.msg.authn-eidas-test.desc");
      isEidas = true;
    }
    else {
      log.error("Uknown LoA: {}", loa);
    }

    return isEidas;
  }

}
