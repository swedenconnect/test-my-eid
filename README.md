![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# test-my-eid

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Test application for testing authentication against Identity Providers in the Sweden Connect federation.

---

The **Test my eID** Spring Boot application is the official test service provider for testing authentication against the identity providers of the Sweden Connect-federation. 

It is released as open source so that anyone can see how an authentication request that is compliant with the [Sweden Connect Technical Framework](https://docs.swedenconnect.se/technical-framework/) should be constructed. The application also contains a reference for how to validate a response message containing an SAML assertion.

**Test my eID** is available in the following federations:

* Sweden Connect Sandbox - [https://eid.idsec.se/testmyeid](https://eid.idsec.se/testmyeid)

	* Note: Not all IdP:s in the sandbox federation is functioning correctly. The Test my eID-application is currently configured to support all IdP:s that seem to be "up".

* Sweden Connect QA - [https://qa.test.swedenconnect.se](https://qa.test.swedenconnect.se)

* Sweden Connect Production - [https://test.swedenconnect.se](https://test.swedenconnect.se)

### Configuration settings

This section describes the configuration settings of the application.

You can start the application by giving property values on the form `-D<property>=<value>` to the Java application. For example:

```
>JAVA_OPTS="-Dserver.port=9443 -Dmanagement.server.port=9444"
>java $JAVA_OPTS test-my-eid-<version>.jar
```

Or, you can assign the corresponding environment variables:

```
>SERVER_PORT=9443
>MANAGEMENT_SERVER_PORT=9444
>java test-my-eid-<version>.jar
```

**General servlet settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `spring.profiles.active`<br />`SPRING_PROFILES_ACTIVE` | The active Spring profile(s). | - |
| `server.port`<br/>`SERVER_PORT` | The server port. | 8443 |
| `server.servlet.context-path`<br />`SERVER_SERVLET_CONTEXT_PATH` | The context path for the application | `/testmyeid` |
| `server.ssl.enabled`<br />`SERVER_SSL_ENABLED` | Is TLS enabled for the application? | `true` |
| `server.ssl.key-store`<br />`SERVER_SSL_KEY_STORE` | The path to the keystore holding the application TLS key and certificate. | `classpath:snakeoil-localhost.p12`<br />Need to be changed to reflect the application host name. Unless running in AJP-mode (see below). |
| `server.ssl.key-store-type`<br />`SERVER_SSL_KEY_STORE_TYPE` | The type of the TLS keystore (PKCS12/JKS). | `PKCS12` |
| `server.ssl.key-store-password`<br />`SERVER_SSL_KEY_STORE_PASSWORD` | The password for the above keystore. | `secret` |
| `server.ssl.key-alias`<br/>`SERVER_SSL_KEY_ALIAS` | The keystore alias holding the TLS key and certificate. | `localhost` |
| `server.ssl.key-password`<br/>`SERVER_SSL_KEY_PASSWORD` | The password to unlock the TLS key. | `secret` |
| `tomcat.ajp.enabled`<br />`TOMCAT_AJP_ENABLED` | Is the AJP protocol enabled? | `false` |
| `tomcat.ajp.port`<br />`TOMCAT_AJP_PORT` | The AJP port. | 8009 |
| `tomcat.ajp.secret-required`<br />`TOMCAT_AJP_SECRET_REQUIRED` | Whether AJP secret is required. | `false` |
| `tomcat.ajp.secret`<br />`TOMCAT_AJP_SECRET` | Tomcat AJP secret. | `-` |

Note that the application also supports the [Spring SSL Bundles](https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl) feature. In these cases the `server.ssl.bundle` setting is assigned a registered SSL bundle.

**Application settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `sp.entity-id`<br />`SP_ENTITY_ID` | The SAML entityID for the **Test my eID** application. | `http://test.swedenconnect.se/testmyeid` |
| `sp.sign-entity-id`<br />`SP_SIGN_ENTITY_ID` | The SAML entityID for the **Test my eID** application when it acts as a signature service. | `http://test.swedenconnect.se/testmyeid-sign` |
| ~~`sign-sp.entity-id`~~<br />~~`SIGN_SP_ENTITY_ID`~~ | Deprecated. Use `sp.sign-entity-id`. | `http://test.swedenconnect.se/testmyeid-sign` |
| `sp.base-uri`<br />`SP_BASE_URI` | The base URI for the SP application, e.g., `https://test.swedenconnect.se`. | - |
| `sp.federation.metadata.url`<br />`SP_FEDERATION_METADATA_URL` | The URL from which federation metadata is periodically downloaded. | For production:<br/> `https://md.swedenconnect.se/role/idp.xml`<br /> For QA:<br/> `https://qa.md.swedenconnect.se/role/idp.xml`<br />For sandbox:<br/> `https://eid.svelegtest.se/metadata/`<br/>`mdx/role/idp.xml` |
| `sp.federation.metadata.`<br />`validation-certificate`<br />`SP_FEDERATION_METADATA_`<br />`VALIDATION_CERTIFICATE` | Path to the certificate that is to be used to verify metadata signatures. The application classpath contains valid certificates for the `sandbox`, `qa` and `prod` profiles. To override any of the default values give the full path prefixed with `file:`. | For production:<br/>`classpath:prod/sc-metadata.crt`<br/>For QA:<br />`classpath:qa/sc-qa-metadata.crt`<br />For sandbox:<br/>`classpath:sandbox/sandbox-metadata.crt` |
| `sp.discovery.`<br/>`static-idp-configuration`<br/>`SP_DISCOVERY_`<br />`STATIC_IDP_CONFIGURATION` | Optional configuration file that tells how the IdP discovery page should be displayed. See further the "IdP Discovery Configuration" section below.<br/>To override a default value give the full path prefixed with `file:`.  | Default (no profile):<br/>-<br />For production:<br/>[`classpath:prod/idp-disco-prod.yml`](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/prod/idp-disco-prod.yml)<br/>For QA:<br/>[`classpath:qa/idp-disco-qa.yml`](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/qa/idp-disco-qa.yml)<br/>For sandbox:<br/>[`classpath:qa/idp-disco-sandbox.yml`](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/sandbox/idp-disco-sandbox.yml) |
| `sp.discovery.black-list`<br />`SP_DISCOVERY_BLACK_LIST` | A list of black-listed IdP:s (entity ID:s) | - |
| `sp.discovery.include-only-static`<br />`SP_DISCOVERY_INCLUDE_ONLY_STATIC` | Whether only statically configured IdP:s should be selectable (see above). | `false` |
| `sp.discovery.cache-time`<br />`SP_DISCOVERY_CACHE_TIME` | Number of seconds the application should keep discovery cache. | `600` (10 minutes) |
| `sp.discovery.ignore-contracts`<br />`SP_DISCOVERY_IGNORE_CONTRACTS` | Should contract entity categories be ignored during discovery matching? | `true` |
| `sp.security.algorithm-config.`<br/>`rsa-oaep-digest`<br/>`SP_SECURITY_ALGORITHM_CONFIG_`<br />`RSA_OAEP_DIGEST` | Which digest method to use as default for RSA-OAEP encryption. Consider using `http://www.w3.org/2000/09/xmldsig#sha1` if we run into too many interop issues with the SHA-256 default. | `http://www.w3.org/2001/04/xmlenc#sha256` |
| ``sp.security.algorithm-config.`<br/>`use-aes-gcm`<br/>`SP_SECURITY_ALGORITHM_CONFIG_`<br />`USE_AES_GCM` | Should AES-GCM block cipher be used? The alternative is AES-CBC. | `true` |

For easy deployment, the **Test my eID** application comes with pre-packaged credentials in form of Java Keystore files. For production these should be changed.

The table below shows the configuration settings for the three credentials used. The `<usage>` stands for:

* `sign` - The credential the SP application uses to sign authentication requests.
* `decrypt` - The credential holding the decryption key (to decrypt assertions).
* `md-sign` - The signature credential used to sign the metadata (published at `/testmyeid/metadata`.

See [Credential Configuration Support](https://docs.swedenconnect.se/credentials-support/#configuration-support) for how configure each credential.

SAML metadata for the SP application is put together using a set of configurable properties and published on `/testmyeid/metadata`. All metadata properties are prefixed with `sp.metadata.` and control entity categories, display name, logotype, organization name and contact details. See further the [application.yml](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/application.yml) file. To override a property simply define your own value for it.


**Management API settings**:

For settings concerning the Spring Boot management API, see the property values prefixed with `management` of [application.yml](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/application.yml).

**Log settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `logging.level.root`<br/>`LOGGING_LEVEL_ROOT` | Default level for logging. | `INFO` |
| `logging.level.testmyeid`<br />`LOGGING_LEVEL_TESTMYEID` | Logging level for Test my eID logic. | `DEBUG` |

For controlling the log level for a specific package assign a property/variable on the format `logging.level.<package-name>`/`LOGGING_LEVEL_<package-name separated with '_'>`.


<a name="idp-discovery-configuration"></a>
#### IdP Discovery Configuration

The page where the user selects which IdP (or authentication method) to use is normally called "IdP Discovery". It is possible to construct such a list only based on the IdP:s found in the SAML metadata, where each IdP declares its display name and logotype. However, for an optimal user interface you may want to add extra information, display a more suitable logotype, filter out some of the IdP:s found and perhaps most important, to display the options in the order that you decide.

Therefore, the **Test my eID** application may be supplied with a IDP discovery configuration file (by assigning the property `sp.discovery.static-idp-configuration`). This configuration file is a list under the `idp` key where each item may contain:

| Property | Description | Default |
| :--- | :--- | :--- |
| `entity-id` | The entityID of the IdP. | Required field - no default |
| `display-name-sv`<br />`display-name-en` | The display name in Swedish/English for the IdP. | IdP metadata entry (`mdui:DisplayName` element with language tag "sv"/"en"). |
| `description-sv`<br />`description-en` | For some IdP:s we may want to add additional information. This property provides this information in Swedish/English. | - |
| `logo-url` | An URL for the IdP logotype that should be displayed in the UI. | IdP metadata entry (`mdui:Logo` element with the most "square" dimensions). |
| `logo-width`<br />`logo-height` | The width/height for `logo-url` | - |
| `enabled` | Enable flag. May be used if a configuration for an IdP is set up, but it should not be active until later. | `true` |

**Example:**

The default IdP configuration file for the Sweden Connect QA profile looks like:

```
idp:
  # The eIDAS connector
  - entity-id: https://qa.connector.eidas.swedenconnect.se/eidas
  # Freja eID Plus
  - entity-id: https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com
    logo-url: https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com/idp/images/frejaeid_logo.svg
    logo-height: 75
    logo-width: 75
  # The Sweden Connect Reference IdP
  - entity-id: http://qa.test.swedenconnect.se/idp
```

### Management API

Somewhat overkill for a test application, but **Test my eID** also has a management API.

Endpoints for monitoring and administering the service can accessed via the management port (default: 8444). This port should not be publicly exposed and is for internal use only. The following endpoints are available:

#### Health - /actuator/health

Returns a general health indication for the service. For an "UP" status, the endpoint will return a 200 HTTP status along with a JSON response that may look something like:

```
curl --insecure https://<server>:8444/actuator/health

{
   "status" : "UP",
   "details" : {
      "diskSpace" : {
         "details" : {
            "free" : 139894284288,
            "threshold" : 10485760,
            "total" : 500068036608
         },
         "status" : "UP"
      },
      "testMyEid" : {
         "status" : "UP"
      }
   }
}
```

If all checks that are performed by the `health`-endpoint returns "UP", the overall status will be "UP" and a 200 HTTP status is returned.

#### Info - /actuator/info

The `/manage/info` endpoint displays information about the service. Spring Boot supplies some information such as build info and version information.

```
curl --insecure https://<server>:8444/actuator/info

{
   "app" : {
      "version" : "1.0.0",
      "name" : "test-my-eid",
      "description" : "Application for testing my eID"
   }
}

```


Copyright &copy; 2016-2025, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
