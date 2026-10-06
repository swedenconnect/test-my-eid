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

import java.util.Objects;

/**
 * Representation of a SAML entityID.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class EntityID {

  /** The entityID. */
  private final @NonNull String entityID;

  /**
   * Constructor.
   *
   * @param entityID the entityID
   */
  public EntityID(final @NonNull String entityID) {
    this.entityID = entityID;
  }

  /**
   * Gets the entityID.
   *
   * @return the entityID
   */
  public @NonNull String getEntityID() {
    return this.entityID;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final @Nullable Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }
    final EntityID other = (EntityID) o;
    return Objects.equals(this.entityID, other.entityID);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.entityID);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "EntityID(entityID=" + this.entityID + ")";
  }

}
