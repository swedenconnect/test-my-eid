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
package se.swedenconnect.eid.sp.utils;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test cases for {@link LogotypeInspector}.
 *
 * @author Martin Lindström
 */
class LogotypeInspectorTest {

  /** A logotype with white text and a small colored mark (like a negative logotype). */
  private static final String WHITE_LOGO = """
      <svg width="121px" height="51px" viewBox="0 0 121 51" xmlns="http://www.w3.org/2000/svg">
        <g fill="none">
          <g fill="#FFFFFF">
            <path d="M0,0 L1,1"/>
            <path d="M0,0 L1,1"/>
            <polygon points="0 0 1 1 2 2"/>
          </g>
          <rect x="80" y="0" width="34" height="34" fill="#FFCC00"/>
        </g>
      </svg>
      """;

  @Test
  void testWhiteLogotype() {
    assertThat(LogotypeInspector.isLightSvg(bytes(WHITE_LOGO))).isTrue();
  }

  @Test
  void testDarkLogotype() {
    assertThat(LogotypeInspector.isLightSvg(bytes(WHITE_LOGO.replace("#FFFFFF", "#1E3557")))).isFalse();
  }

  @Test
  void testDefaultFillIsBlack() {
    assertThat(LogotypeInspector.isLightSvg(bytes("""
        <svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg"><path d="M0,0 L1,1"/></svg>"""))).isFalse();
  }

  @Test
  void testOwnBackground() {
    assertThat(LogotypeInspector.isLightSvg(bytes("""
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
          <rect width="100" height="100" rx="10" fill="#235971"/>
          <path d="M0,0 L1,1" fill="white"/>
          <path d="M0,0 L1,1" fill="white"/>
        </svg>"""))).isFalse();
  }

  @Test
  void testCssClassesAndStyle() {
    assertThat(LogotypeInspector.isLightSvg(bytes("""
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
          <style>.st0, .st1 { fill: #FFF; } .st2 { fill: #000; }</style>
          <path class="st0" d="M0,0 L1,1"/>
          <path class="st1" d="M0,0 L1,1"/>
          <path style="fill:rgb(250, 250, 250)" d="M0,0 L1,1"/>
          <path class="st2" d="M0,0 L1,1"/>
        </svg>"""))).isTrue();
  }

  @Test
  void testDefsAreIgnored() {
    assertThat(LogotypeInspector.isLightSvg(bytes("""
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
          <defs><path fill="#FFF" d="M0,0"/><path fill="#FFF" d="M0,0"/></defs>
          <path fill="#000" d="M0,0 L1,1"/>
        </svg>"""))).isFalse();
  }

  @Test
  void testInvalidSvg() {
    assertThat(LogotypeInspector.isLightSvg(bytes("not xml"))).isFalse();
    assertThat(LogotypeInspector.isLightSvg(bytes("<html/>"))).isFalse();
  }

  @Test
  void testDataUrl() {
    final LogotypeInspector inspector = new LogotypeInspector(600);
    try {
      assertThat(inspector.isLightLogotype(
          "data:image/svg+xml;base64," + Base64.getEncoder().encodeToString(bytes(WHITE_LOGO)))).isTrue();
      assertThat(inspector.isLightLogotype("data:image/png;base64,AAAA")).isFalse();
      assertThat(inspector.isLightLogotype(null)).isFalse();
    }
    finally {
      inspector.destroy();
    }
  }

  @Test
  void testParseColor() {
    assertThat(LogotypeInspector.parseColor("#fff")).containsExactly(255, 255, 255);
    assertThat(LogotypeInspector.parseColor("#FFCC00")).containsExactly(255, 204, 0);
    assertThat(LogotypeInspector.parseColor("rgb(1,2,3)")).containsExactly(1, 2, 3);
    assertThat(LogotypeInspector.parseColor("White")).containsExactly(255, 255, 255);
    assertThat(LogotypeInspector.parseColor("none")).isNull();
    assertThat(LogotypeInspector.parseColor("url(#gradient)")).isNull();
  }

  private static byte[] bytes(final String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

}
