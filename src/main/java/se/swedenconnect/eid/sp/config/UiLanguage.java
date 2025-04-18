/*
 * Copyright 2018-2025 Sweden Connect
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

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * Model class for representing a selectable language in the UI.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Data
@NoArgsConstructor
@ToString
public class UiLanguage {

  /**
   * The language tag, i.e., "en".
   */
  private String languageTag;

  /**
   * The text to display for the language, i.e., "English".
   */
  private String text;

}
