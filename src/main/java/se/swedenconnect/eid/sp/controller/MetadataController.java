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

import java.io.ByteArrayOutputStream;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.w3c.dom.Element;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;

/**
 * Controller for displaying SP metadata.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Controller
@RequestMapping("/metadata")
@Slf4j
public class MetadataController {

  /** Media type for SAML metadata in XML format. */
  public static final String APPLICATION_SAML_METADATA = "application/samlmetadata+xml";

  @Autowired
  @Qualifier("spEntityDescriptorContainer")
  private EntityDescriptorContainer metadataContainer;

  @Autowired
  @Qualifier("signSpEntityDescriptorContainer")
  private EntityDescriptorContainer signSpMetadataContainer;

  @GetMapping
  @ResponseBody
  public HttpEntity<byte[]> getMetadata(final HttpServletRequest request,
      @RequestHeader(name = "Accept", required = false) final String acceptHeader) {
    return this.getMetadata(this.metadataContainer, request, acceptHeader);
  }

  @GetMapping("/sign")
  @ResponseBody
  public HttpEntity<byte[]> getSignSpMetadata(final HttpServletRequest request,
      @RequestHeader(name = "Accept", required = false) final String acceptHeader) {
    return this.getMetadata(this.signSpMetadataContainer, request, acceptHeader);
  }

  private HttpEntity<byte[]> getMetadata(final EntityDescriptorContainer metadata, final HttpServletRequest request,
      final String acceptHeader) {

    log.debug("Request to download metadata from {}", request.getRemoteAddr());

    try {

      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (metadata.updateRequired(true)) {
        log.debug("Metadata needs to be updated ...");
        metadata.update(true);
        log.debug("Metadata was updated and signed");
      }
      else {
        log.debug("Metadata is up-to-date, using cached metadata");
      }

      // Get the DOM for the metadata and serialize it.
      //
      final Element dom = metadata.marshall();

      final ByteArrayOutputStream stream = new ByteArrayOutputStream();
      SerializeSupport.writeNode(dom, stream);

      // Assign the HTTP headers.
      //
      final HttpHeaders header = new HttpHeaders();
      if (acceptHeader != null && !acceptHeader.contains(APPLICATION_SAML_METADATA)) {
        header.setContentType(MediaType.APPLICATION_XML);
      }
      else {
        header.setContentType(MediaType.valueOf(APPLICATION_SAML_METADATA));
      }

      final byte[] documentBody = stream.toByteArray();
      header.setContentLength(documentBody.length);
      return new HttpEntity<>(documentBody, header);
    }
    catch (final SignatureException | MarshallingException e) {
      log.error("Failed to return valid metadata", e);
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
