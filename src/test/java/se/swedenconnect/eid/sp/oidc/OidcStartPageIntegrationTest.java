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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests the mixed IdP/OP list on the start page.
 */
class OidcStartPageIntegrationTest {

  private static final String OP1 = "rp.providers[0].issuer=https://op1.example.com";

  private static final String OP1_DOC = "rp.providers[0].discovery-document-resource=classpath:test-ops/op1.json";

  private static final String OP2 = "rp.providers[1].issuer=https://op2.example.com";

  private static final String OP2_DOC = "rp.providers[1].discovery-document-resource=classpath:test-ops/op2.json";

  private static final String OP3 = "rp.providers[2].issuer=https://op3.example.com";

  private static final String OP3_DOC = "rp.providers[2].discovery-document-resource=classpath:test-ops/op3.json";

  private static final String OP4 = "rp.providers[3].issuer=https://op4.example.com";

  private static final String OP4_DOC = "rp.providers[3].discovery-document-resource=classpath:test-ops/op4.json";

  private static final String OP2_FIRST = "rp.providers[0].issuer=https://op2.example.com";

  private static final String OP2_DOC_FIRST = "rp.providers[0].discovery-document-resource=classpath:test-ops/op2.json";

  private static String startPage(final WebApplicationContext context) throws Exception {
    return MockMvcBuilders.webAppContextSetup(context).build()
        .perform(get("/")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
  }

  @Nested
  @SpringBootTest(properties = { OP1, OP1_DOC, OP2, OP2_DOC, OP3, OP3_DOC, OP4, OP4_DOC,
      "rp.discovery.black-list=https://op3.example.com",
      "sp.discovery.static-idp-configuration=classpath:test-static-mixed.yml" })
  @ActiveProfiles("test")
  class MixedList {

    @Autowired
    private WebApplicationContext context;

    @Test
    void ordersRenamesDisablesAndBlackLists() throws Exception {
      final String html = startPage(this.context);

      // Static entries first in configured order, then the remaining IdPs, then the remaining OPs
      final int op2 = html.indexOf("Second OP");
      final int idp = html.indexOf("Test IdP");
      final int op1 = html.indexOf("OP One");
      assertThat(op2).isPositive();
      assertThat(idp).isGreaterThan(op2);
      assertThat(op1).isGreaterThan(idp);

      assertThat(html).contains("A renamed OP");
      assertThat(html).contains("https://op1.example.com/logo.svg");
      assertThat(html).contains("OpenID Connect").contains("SAML");
      assertThat(html).contains("name=\"selectedOp\"").contains("value=\"https://op1.example.com\"");

      // Disabled through the static file, and black-listed
      assertThat(html).doesNotContain("https://op4.example.com");
      assertThat(html).doesNotContain("https://op3.example.com");
    }
  }

  @Nested
  @SpringBootTest(properties = { OP1, OP1_DOC, OP2, OP2_DOC, OP3, OP3_DOC, OP4, OP4_DOC,
      "sp.discovery.static-idp-configuration=classpath:test-static-mixed.yml",
      "sp.discovery.include-only-static=true" })
  @ActiveProfiles("test")
  class OnlyStatic {

    @Autowired
    private WebApplicationContext context;

    @Test
    void onlyStaticEntriesAreListed() throws Exception {
      final String html = startPage(this.context);
      assertThat(html).contains("Second OP").contains("Test IdP");
      assertThat(html).doesNotContain("OP One");
    }
  }

  @Nested
  @SpringBootTest(properties = { OP2_FIRST, OP2_DOC_FIRST })
  @ActiveProfiles("test")
  class IssuerAsName {

    @Autowired
    private WebApplicationContext context;

    @Test
    void issuerIsUsedWhenMetadataHasNoName() throws Exception {
      final String html = startPage(this.context);
      assertThat(html).contains(">https://op2.example.com<");
    }
  }

}
