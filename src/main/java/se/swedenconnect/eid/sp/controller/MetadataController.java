/*
 * Copyright 2018 Sweden Connect
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

import javax.servlet.http.HttpServletRequest;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
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

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.litsec.opensaml.saml2.metadata.EntityDescriptorContainer;

/**
 * Controller for displaying SP metadata.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@Controller
@RequestMapping("/metadata")
@Slf4j
public class MetadataController {
  
  /** Media type for SAML metadata in XML format. */
  public static final String APPLICATION_SAML_METADATA = "application/samlmetadata+xml";
  
  @Autowired
  private EntityDescriptorContainer metadataContainer;

  @GetMapping
  @ResponseBody
  public HttpEntity<byte[]> getMetadata(HttpServletRequest request, @RequestHeader(name = "Accept", required = false) String acceptHeader) {
    
    log.debug("Request to download metadata from {}", request.getRemoteAddr());
    
    try {

      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (this.metadataContainer.updateRequired(true)) {
        log.debug("Metadata needs to be updated ...");
        this.metadataContainer.update(true);
        log.debug("Metadata was updated and signed");
      }
      else {
        log.debug("Metadata is up-to-date, using cached metadata");
      }

      // Get the DOM for the metadata and serialize it.
      //
      Element dom = this.metadataContainer.marshall();

      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      SerializeSupport.writeNode(dom, stream);

      // Assign the HTTP headers.
      //
      HttpHeaders header = new HttpHeaders();
      if (acceptHeader != null && !acceptHeader.contains(APPLICATION_SAML_METADATA)) {
        header.setContentType(MediaType.APPLICATION_XML);
      }
      else {
        header.setContentType(MediaType.valueOf(APPLICATION_SAML_METADATA));
      }

      byte[] documentBody = stream.toByteArray();
      header.setContentLength(documentBody.length);
      return new HttpEntity<byte[]>(documentBody, header);
    }
    catch (SignatureException | MarshallingException e) {
      log.error("Failed to return valid metadata", e);
      return new ResponseEntity<byte[]>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
