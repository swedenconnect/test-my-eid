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
package se.swedenconnect.eid.sp.oidc.federation;

import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import se.swedenconnect.eid.sp.oidc.TestSupport;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link EntityConfigurationService}.
 */
class EntityConfigurationServiceTest {

  @Test
  void keepsSignatureUntilHalfLifetime() throws Exception {
    final TestSupport.MutableClock clock = new TestSupport.MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    final EntityConfigurationService service =
        new EntityConfigurationService(TestSupport.relyingParty(), Duration.ofDays(7), clock);

    final SignedJWT first = service.getEntityConfiguration();
    assertThat(first.getJWTClaimsSet().getExpirationTime().toInstant())
        .isEqualTo(Instant.parse("2026-01-08T00:00:00Z"));

    clock.advance(Duration.ofDays(3).plusHours(11));
    assertThat(service.getEntityConfiguration().serialize()).isEqualTo(first.serialize());

    clock.advance(Duration.ofHours(1));
    final SignedJWT second = service.getEntityConfiguration();
    assertThat(second.serialize()).isNotEqualTo(first.serialize());
    assertThat(second.getJWTClaimsSet().getIssueTime().toInstant())
        .isEqualTo(Instant.parse("2026-01-04T12:00:00Z"));
  }

  @Test
  void signsAnewWhenContentChanges() throws Exception {
    final TestSupport.MutableClock clock = new TestSupport.MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    final EntityConfigurationService service =
        new EntityConfigurationService(TestSupport.relyingParty(), Duration.ofDays(7), clock);
    final List<String> hints = new ArrayList<>();
    service.setAuthorityHintsSupplier(() -> List.copyOf(hints));

    final SignedJWT first = service.getEntityConfiguration();
    assertThat(first.getJWTClaimsSet().getClaim("authority_hints")).isNull();

    clock.advance(Duration.ofMinutes(1));
    hints.add("https://intermediate.example.com");
    final SignedJWT second = service.getEntityConfiguration();
    assertThat(second.serialize()).isNotEqualTo(first.serialize());
    assertThat(second.getJWTClaimsSet().getStringListClaim("authority_hints"))
        .containsExactly("https://intermediate.example.com");

    clock.advance(Duration.ofMinutes(1));
    assertThat(service.getEntityConfiguration().serialize()).isEqualTo(second.serialize());

    final JSONObject mark = new JSONObject();
    mark.put("trust_mark_type", "https://example.com/tm");
    mark.put("trust_mark", "a.b.c");
    service.setTrustMarksSupplier(() -> List.of(mark));
    final SignedJWT third = service.getEntityConfiguration();
    assertThat(third.serialize()).isNotEqualTo(second.serialize());
    assertThat(third.getJWTClaimsSet().getListClaim("trust_marks")).hasSize(1);
  }

}
