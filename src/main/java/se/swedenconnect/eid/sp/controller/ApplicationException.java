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
package se.swedenconnect.eid.sp.controller;

import org.springframework.util.Assert;

/**
 * Exception class for errors during processing. Holds a message code for the error UI.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class ApplicationException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = 1564108817874835701L;

  /** The message code. */
  private final String messageCode;

  /**
   * Constructor assigning the message code for the error.
   *
   * @param messageCode the message code
   */
  public ApplicationException(final String messageCode) {
    Assert.hasText(messageCode, "messageCode must not be null or empty");
    this.messageCode = messageCode;
  }

  /**
   * Constructor assigning the message code and the message text for the error.
   *
   * @param messageCode the message code
   * @param message the error message
   */
  public ApplicationException(final String messageCode, final String message) {
    super(message);
    this.messageCode = messageCode;
  }

  /**
   * Constructor assigning the message code and the cause of the error.
   *
   * @param messageCode the message code
   * @param cause the cause of the error
   */
  public ApplicationException(final String messageCode, final Throwable cause) {
    super(cause.getMessage(), cause);
    this.messageCode = messageCode;
  }

  /**
   * Constructor assigning the message code, the message text and the cause of the error.
   *
   * @param messageCode the message code
   * @param message the error message
   * @param cause the cause of the error
   */
  public ApplicationException(final String messageCode, final String message, final Throwable cause) {
    super(message, cause);
    this.messageCode = messageCode;
  }

  /**
   * Returns the message code.
   *
   * @return the message code
   */
  public String getMessageCode() {
    return this.messageCode;
  }

}
