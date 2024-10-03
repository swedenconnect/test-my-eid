/*
 * Copyright 2018-2024 Sweden Connect
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
package se.swedenconnect.eid.sp;

import java.time.Duration;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import lombok.Setter;
import se.swedenconnect.eid.sp.config.AlgorithmConfiguration.CustomAlgorithms;
import se.swedenconnect.eid.sp.saml.CustomSwedishEidSecurityConfiguration;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;

/**
 * Application main.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@SpringBootApplication
public class TestMyEidApplication {

  @Setter
  @Autowired
  CustomAlgorithms algorithmConfiguration;

  /**
   * Program main.
   *
   * @param args program arguments
   */
  public static void main(final String[] args) {
    SpringApplication.run(TestMyEidApplication.class, args);
  }

  @Bean("openSAML")
  OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance()
        .initialize(
            new OpenSAMLSecurityDefaultsConfig(new CustomSwedishEidSecurityConfiguration(this.algorithmConfiguration)),
            new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

  @Bean
  LocaleResolver localeResolver(@Value("${server.servlet.context-path}") final String contextPath) {
    final CookieLocaleResolver resolver = new CookieLocaleResolver();
    resolver.setDefaultLocale(new Locale("en"));
    resolver.setCookiePath(contextPath);
    resolver.setCookieMaxAge(Duration.ofDays(365));
    return resolver;
  }

  @Configuration
  public static class WebMvcConfig implements WebMvcConfigurer {

    @Bean
    LocaleChangeInterceptor localeChangeInterceptor() {
      final LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
      interceptor.setParamName("lang");
      return interceptor;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
      registry.addInterceptor(this.localeChangeInterceptor());
    }

  }

}
