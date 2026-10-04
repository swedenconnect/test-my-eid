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

import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import se.oidc.nimbus.usermessage.UserMessage;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the Base64 encoding of user messages and sign messages.
 */
class UserMessageEncodingTest {

  @Test
  void specificationExample() {
    // Example from Signature Extension for OpenID Connect 1.1, Section 3.1
    final JSONObject json = OidcRequestFactory.encode(new UserMessage(List.of(
        new UserMessage.Message("I hereby agree to the contract displayed", "en"),
        new UserMessage.Message("Jag samtycker härmed till kontraktet som visats", "sv")),
        UserMessage.TEXT_MIME_TYPE));
    assertThat(json.get("message#en")).isEqualTo("SSBoZXJlYnkgYWdyZWUgdG8gdGhlIGNvbnRyYWN0IGRpc3BsYXllZA==");
    assertThat(json.get("message#sv")).isEqualTo("SmFnIHNhbXR5Y2tlciBow6RybWVkIHRpbGwga29udHJha3RldCBzb20gdmlzYXRz");
    assertThat(json.get("mime_type")).isEqualTo("text/plain");
    assertThat(json).containsOnlyKeys("message#en", "message#sv", "mime_type");
  }

  @Test
  void untaggedMessage() {
    final JSONObject json = OidcRequestFactory.encode(new UserMessage(
        List.of(new UserMessage.Message("Hej!")), UserMessage.TEXT_MIME_TYPE));
    assertThat(json).containsOnlyKeys("message", "mime_type");
    assertThat(TestSupport.decode(json.get("message"))).isEqualTo("Hej!");
  }

  @Test
  void markdownWithNonAsciiAndLineBreaksIsKept() {
    final String markdown = "# Testa mitt eID\n\n**Notera:** Detta är en testlegitimering – åäö ÅÄÖ € 😀\n";
    final JSONObject json = OidcRequestFactory.encode(new UserMessage(
        List.of(new UserMessage.Message(markdown, "sv")), UserMessage.MARKDOWN_MIME_TYPE));
    final String encoded = (String) json.get("message#sv");
    // Standard Base64 alphabet, no line breaks
    assertThat(encoded).matches("[A-Za-z0-9+/]+=*");
    assertThat(TestSupport.decode(encoded)).isEqualTo(markdown);
    assertThat(json.get("mime_type")).isEqualTo("text/markdown");
  }

  @Test
  void emptyMessage() {
    final JSONObject json = OidcRequestFactory.encode(new UserMessage(
        List.of(new UserMessage.Message("", "en")), UserMessage.TEXT_MIME_TYPE));
    assertThat(json.get("message#en")).isEqualTo("");
  }

}
