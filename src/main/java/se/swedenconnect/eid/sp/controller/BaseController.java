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
package se.swedenconnect.eid.sp.controller;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.jspecify.annotations.NonNull;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;

import se.swedenconnect.eid.sp.config.UiLanguage;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation;
import se.swedenconnect.eid.sp.model.IdpDiscoveryInformation.IdpModel;
import se.swedenconnect.eid.sp.utils.LogotypeInspector;

/**
 * Base controller.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class BaseController {

  /** Possible languages for the UI. */
  @Autowired
  protected @NonNull List<UiLanguage> languages;

  /** Checks whether logotypes need a dark background. */
  @Autowired
  protected @NonNull LogotypeInspector logotypeInspector;

  /**
   * Updates the MVC model with common attributes such as possible languages.
   *
   * @param model the model
   */
  @ModelAttribute
  public void updateModel(final @NonNull Model model) {
    final Locale locale = LocaleContextHolder.getLocale();

    model.addAttribute("languages", this.languages.stream()
        .filter(lang -> !lang.getLanguageTag().equals(locale.getLanguage()))
        .collect(Collectors.toList()));
  }

  /**
   * Creates the UI model for an IdP or OP.
   *
   * @param idp the IdP or OP information
   * @return the UI model
   */
  protected @NonNull IdpModel toIdpModel(final @NonNull IdpDiscoveryInformation idp) {
    final IdpModel model = idp.getIdpModel(LocaleContextHolder.getLocale());
    model.setDarkLogotypeBackground(this.logotypeInspector.isLightLogotype(model.getLogotype()));
    return model;
  }

}
