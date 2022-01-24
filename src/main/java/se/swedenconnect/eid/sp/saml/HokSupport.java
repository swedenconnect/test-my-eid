/*
 * Copyright 2018-2021 Sweden Connect
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
package se.swedenconnect.eid.sp.saml;

/**
 * Enum for selecting HoK or not.
 * 
 * @author Martin Lindström (martin@idsec.se)
 */
public enum HokSupport {
  
  /** Holder of key is not supported by the IdP. */
  NONE("none"),
  
  /** The IdP only supports HoK. */
  ONLY_HOK("only_hok"),
  
  /** The IdP supports both Holder-of-key and plain WebSSO. */
  BOTH("both");
  
  public String getName() {
    return this.name;
  }
  
  public static HokSupport parse(final String name) {
    for (final HokSupport hs : HokSupport.values()) {
      if (hs.getName().equalsIgnoreCase(name)) {
        return hs;
      }
    }
    throw new IllegalArgumentException(name + " is not a valid string");
  }
  
  private HokSupport(final String name) {
    this.name = name;
  }
  
  private final String name;
}
