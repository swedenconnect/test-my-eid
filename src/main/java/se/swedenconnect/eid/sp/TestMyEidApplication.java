/*
 * Copyright 2018-2019 Sweden Connect
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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mobile.device.DeviceHandlerMethodArgumentResolver;
import org.springframework.mobile.device.DeviceResolverHandlerInterceptor;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import se.swedenconnect.eid.sp.config.AlgorithmConfiguration;
import se.swedenconnect.eid.sp.config.UiLanguage;
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
  
  @Autowired
  AlgorithmConfiguration algorithmConfiguration;

  /**
   * Program main.
   * 
   * @param args
   *          program arguments
   */
  public static void main(String[] args) {
    SpringApplication.run(TestMyEidApplication.class, args);
  }

  @Bean("openSAML")
  public OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance()
      .initialize(
        new OpenSAMLSecurityDefaultsConfig(new CustomSwedishEidSecurityConfiguration(this.algorithmConfiguration)),
        new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

  @Bean
  public LocaleResolver localeResolver(@Value("${server.servlet.context-path}") String contextPath) {
    CookieLocaleResolver resolver = new CookieLocaleResolver();
    resolver.setDefaultLocale(new Locale("en"));
    resolver.setCookiePath(contextPath);
    resolver.setCookieMaxAge(31536000);
    return resolver;
  }

  @Bean
  @ConfigurationProperties(prefix = "sp.ui.lang")
  public List<UiLanguage> languages() {
    return new ArrayList<>();
  }

  @Configuration
  public static class WebMvcConfig implements WebMvcConfigurer {

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
      LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
      interceptor.setParamName("lang");
      return interceptor;
    }

    @Bean
    public DeviceResolverHandlerInterceptor deviceResolverHandlerInterceptor() {
      return new DeviceResolverHandlerInterceptor();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
      registry.addInterceptor(localeChangeInterceptor());
      registry.addInterceptor(deviceResolverHandlerInterceptor());
    }

    @Bean
    public DeviceHandlerMethodArgumentResolver deviceHandlerMethodArgumentResolver() {
      return new DeviceHandlerMethodArgumentResolver();
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
      argumentResolvers.add(deviceHandlerMethodArgumentResolver());
    }

  }
  
}
