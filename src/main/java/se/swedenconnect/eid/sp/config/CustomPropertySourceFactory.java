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
package se.swedenconnect.eid.sp.config;

import java.io.IOException;
import java.util.Optional;
import java.util.Properties;

import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.DefaultPropertySourceFactory;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

/**
 * A {@link PropertySourceFactory} that handles both YAML files and properties files.
 *
 * @author Martin Lindström
 */
public class CustomPropertySourceFactory extends DefaultPropertySourceFactory {

  @Override
  public PropertySource<?> createPropertySource(final String name, final EncodedResource resource) throws IOException {

    if (isYamlFile(resource.getResource())) {
      final YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
      factory.setResources(resource.getResource());

      final Properties properties = factory.getObject();

      return new PropertiesPropertySource(resource.getResource().getFilename(), properties);
    }
    else {
      return super.createPropertySource(name, resource);
    }
  }

  private static final boolean isYamlFile(final Resource resource) {
    if (!resource.isFile()) {
      return false;
    }
    final String ext = Optional.ofNullable(resource.getFilename())
        .filter(f -> f.contains("."))
        .map(f -> f.substring(f.lastIndexOf(".") + 1))
        .orElse("");

    return "yml".equalsIgnoreCase(ext) || "yaml".equalsIgnoreCase(ext);
  }

}
