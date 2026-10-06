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

/**
 * Model class for representing a selectable language in the UI.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class UiLanguage {

  /**
   * The language tag, i.e., "en".
   */
  private @Nullable String languageTag;

  /**
   * The text to display for the language, i.e., "English".
   */
  private @Nullable String text;

  /**
   * Gets the language tag, i.e., "en".
   *
   * @return the language tag
   */
  public @Nullable String getLanguageTag() {
    return this.languageTag;
  }

  /**
   * Assigns the language tag, i.e., "en".
   *
   * @param languageTag the language tag
   */
  public void setLanguageTag(final @Nullable String languageTag) {
    this.languageTag = languageTag;
  }

  /**
   * Gets the text to display for the language, i.e., "English".
   *
   * @return the text
   */
  public @Nullable String getText() {
    return this.text;
  }

  /**
   * Assigns the text to display for the language, i.e., "English".
   *
   * @param text the text
   */
  public void setText(final @Nullable String text) {
    this.text = text;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "UiLanguage(languageTag=" + this.languageTag + ", text=" + this.text + ")";
  }

}
