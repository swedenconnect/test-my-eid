![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# test-my-eid

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Test application for testing authentication against Identity Providers in the Sweden Connect federation.

---

The **Test my eID** Spring Boot application is the official test service provider for testing authentication against the identity providers of the Sweden Connect-federation. 

It is released as open source so that anyone can see how an authentication request that is compliant with the [Sweden Connect Technical Framework](https://docs.swedenconnect.se/technical-framework/) should be constructed. The application also contains a reference for how to validate a response message containing an SAML assertion.

**Test my eID** is available in the following federations:

* Sweden Connect Sandbox - [https://eid.idsec.se/testmyeid](https://eid.idsec.se/testmyeid)

	* Note: Not all IdP:s in the sandbox federation is functioning correctly. The Test my eID-application is currently configured to support all IdP:s that seem to be "up". Anyone adding a new IdP to the sandbox-federation and wants that to be supported by the test application should send a mail to [info@idsec.se](mailto:info@idsec.se).

* Sweden Connect QA - *To be added*

* Sweden Connect Production - *To be added*

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

The **Test my eID** application has four pre-defined Spring profiles (that are mutually exclusive). They are `prod`, for Sweden Connect production, `qa`, for running in the Sweden Connect QA federation, `sandbox`, for the Sweden Connect Sandbox federation and `local` for local deployment.

See the corresponding `application-<profile>.properties` files under [src/main/resources](https://github.com/swedenconnect/test-my-eid/tree/master/src/main/resources) for the default values for each profile.

**General servlet settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `spring.profiles.active`<br />`SPRING_PROFILES_ACTIVE` | The active Spring profile(s). Built in support for `prod`, `qa` and `sandbox` is available. They contain default settings (see below) for Sweden Connect production, Sweden Connect QA and Sweden Connect Sandbox. | - |
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
| `tomcat.ajp.remoteauthentication`<br />`TOMCAT_AJP_`<br />`REMOTEAUTHENTICATION` | Whether remote authentication for AJP is required. | `false` |

**Application settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `sp.entity-id`<br />`SP_ENTITY_ID` | The SAML entityID for the **Test my eID** application. | `http://test.swedenconnect.se/testmyeid` |
| `sp.base-uri`<br />`SP_BASE_URI` | The base URI for the SP application, e.g., `https://test.swedenconnect.se`. | - |
| `sp.federation.metadata.url`<br />`SP_FEDERATION_METADATA_URL` | The URL from which federation metadata is periodically downloaded. | For production:<br/> `https://md.swedenconnect.se/role/idp.xml`<br /> For QA:<br/> `https://qa.md.swedenconnect.se/role/idp.xml`<br />For sandbox:<br/> `https://eid.svelegtest.se/metadata/`<br/>`mdx/role/idp.xml` |
| `sp.federation.metadata.`<br />`validation-certificate`<br />`SP_FEDERATION_METADATA_`<br />`VALIDATION_CERTIFICATE` | Path to the certificate that is to be used to verify metadata signatures. The application classpath contains valid certificates for the `sandbox`, `qa` and `prod` profiles. To override any of the default values give the full path prefixed with `file:`. | For production:<br/>`classpath:prod/sc-metadata.crt`<br/>For QA:<br />`classpath:qa/sc-qa-metadata.crt`<br />For sandbox:<br/>`classpath:sandbox/sandbox-metadata.crt` |
| `sp.discovery.`<br/>`static-idp-configuration`<br/>`SP_DISCOVERY_`<br />`STATIC_IDP_CONFIGURATION` | Optional configuration file that tells how the IdP discovery page should be displayed. See further the [IdP Discovery Configuration](#idp-discovery-configuration) section below.<br/>To override a default value give the full path prefixed with `file:`.  | Default (no profile):<br/>-<br />For production:<br/>[`classpath:prod/idp-disco-prod.properties`](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/prod/idp-disco-prod.properties)<br/>For QA:<br/>[`classpath:qa/idp-disco-qa.properties`](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/qa/idp-disco-qa.properties)<br/>For sandbox:<br/>[`classpath:qa/idp-disco-sandbox.properties`](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/sandbox/idp-disco-sandbox.properties) |
| `sp.discovery.cache-time`<br />`SP_DISCOVERY_CACHE_TIME` | Number of seconds the application should keep discovery cache. | `600` (10 minutes) |
| `sp.discovery.ignore-contracts`<br />`SP_DISCOVERY_IGNORE_CONTRACTS` | Should contract entity categories be ignored during discovery matching? | `false` for production and `true` otherwise. |

For easy deployment, the **Test my eID** application comes with pre-packaged credentials in form of Java Keystore files. For production these should be changed.

The table below shows the configuration settings for the three credentials used. The `<usage>` stands for:

* `sign` - The credential the SP application uses to sign authentication requests.
* `decrypt` - The credential holding the decryption key (to decrypt assertions).
* `md-sign` - The signature credential used to sign the metadata (published at `/testmyeid/metadata`.

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `sp.credential.<usage>.file`<br />`SP_CREDENTIAL_<usage>_FILE` | The file holding the keystore file. To override the default setting give the full path prefixed with `file:` | For sign and decrypt:<br />`classpath:sp-keys.jks`<br />For metadata sign:<br />`classpath:metadata-sign.jks` |
| `sp.credential.<usage>.type`<br />`SP_CREDENTIAL_<usage>_type` | The type of keystore - `JKS` or `PKCS12`. | `JKS` |
| `sp.credential.<usage>.password`<br />`SP_CREDENTIAL_<usage>_PASSWORD` | The password to unlock the keystore. | `secret` |
| `sp.credential.<usage>.alias`<br />`SP_CREDENTIAL_<usage>_ALIAS` | The alias for the key entry in the store. | For sign: `sign`<br />For decrypt: `encrypt`<br/>For metadata sign: `mdsign` |
| `sp.credential.<usage>.key-password`<br />`SP_CREDENTIAL_<usage>_KEY_PASSWORD` | The password to unlock the key entry. | `secret` |

SAML metadata for the SP application is put together using a set of configurable properties and published on `/testmyeid/metadata`. All metadata properties are prefixed with `sp.metadata.` and control entity categories, display name, logotype, organization name and contact details. See further the [application.properties](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/application.properties) file. To override a property simply define your own value for it.


**Management API settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `management.server.port`<br />`MANAGEMENT_SERVER_PORT` | The port on which the application listens for management operations (see below). | `8444` |
| `management.server.servlet.context-path`<br/>`MANAGEMENT_SERVER_`<br/>`SERVLET_CONTEXT_PATH` | The context path for the management API. | `${server.servlet.context-path}` |
| `management.endpoints.web.base-path`<br />`MANAGEMENT_ENDPOINTS_`<br/>`WEB_BASE_PATH` | The base path for the management API. | `/manage` |
| `management.server.ssl.*`<br/>`MANAGEMENT_SERVER_SSL_*` | TLS settings for the management API. | Same values as for `server.ssl.*` |

For other settings concerning the Spring Boot management API, see the property values prefixed with `management` of [application.properties](https://github.com/swedenconnect/test-my-eid/blob/master/src/main/resources/application.properties).

**Log settings**:

| Property<br />Environment variable | Description | Default value |
| :--- | :--- | :--- |
| `logging.level.root`<br/>`LOGGING_LEVEL_ROOT` | Default level for logging. | `INFO` |
| `logging.level.testmyeid`<br />`LOGGING_LEVEL_TESTMYEID` | Logging level for Test my eID logic. | `DEBUG` |

For controlling the log level for a specific package assign a property/variable on the format `logging.level.<package-name>`/`LOGGING_LEVEL_<package-name separated with '_'>`.


<a name="idp-discovery-configuration"></a>
#### IdP Discovery Configuration

The page where the user selects which IdP (or authentication method) to use is normally called "IdP Discovery". It is possible to construct such a list only based on the IdP:s found in the SAML metadata, where each IdP declares its display name and logotype. However, for an optimal user interface you may want to add extra information, display a more suitable logotype, filter out some of the IdP:s found and perhaps most important, to display the options in the order that you decide.

Therefore, the **Test my eID** application may be supplied with a IDP discovery configuration file (by assigning the property `sp.discovery.static-idp-configuration`). This configuration file has the following properties:

* `include-unlisted` - A boolean that tells whether an IdP found in the federation metadata that is not listed among the statically configured IdP:s (see below) should be displayed as a selectable option in the discovery UI. The default is `true`.

* `black-list` - A list containing entityID:s of IdP:s that should not be visible in the discovery UI. This list is only valid if `include-unlisted` is `true`. Example:

```
    black-list[0]=http://bad.idp.com
    black-list[1]=http://www.acme.com/idp
```

* `idp.<symbolic-name>` - A map of statically configured IdP:s. See table below.

| Property | Description | Default |
| :--- | :--- | :--- |
| `entity-id` | The entityID of the IdP. | Required field - no default |
| `sort-order` | The order index. The discovery UI will display the IdP:s in order starting with the lowest sort order (0). | `MAX_INT` |
| `display-name-sv`<br />`display-name-en` | The display name in Swedish/English for the IdP. | IdP metadata entry (`mdui:DisplayName` element with language tag "sv"/"en"). |
| `description-sv`<br />`description-en` | For some IdP:s we may want to add additional information. This property provides this information in Swedish/English. | - |
| `logo-url` | An URL for the IdP logotype that should be displayed in the UI. | IdP metadata entry (`mdui:Logo` element with the most "square" dimensions). |
| `logo-width`<br />`logo-height` | The width/height for `logo-url` | - |
| `mobile-use` | Can this IdP be used by users having a mobile device? | `true` if the IdP metadata entry declares the entity category [mobile-auth](http://docs.swedenconnect.se/technical-framework/updates/ELN-0606_-_Entity_Categories_for_the_Swedish_eID_Framework.html#mobile-auth) and `false` otherwise. |
| `enabled` | Enable flag. May be used if a configuration for an IdP is set up, but it should not be active until later. | `true` |
| `skip-entity-category-matching` | Even if an IdP is statically configured, the **Test my eID** will check if it is usable for the SP by matching the SP entity categories against the IdP entity categories according to the [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/updates/ELN-0606_-_Entity_Categories_for_the_Swedish_eID_Framework.html#consuming-and-providing-services) specification. By setting this value to `false` no such checks are made. | `false` |

**Example:**

The default IdP configuration file for the Sweden Connect QA profile looks like:

```
include-unlisted=false

idp.eidas.entity-id=https://qa.connector.eidas.swedenconnect.se/eidas
idp.eidas.sort-order=0

# Freja defines two logotypes. We control which is displayed.
idp.freja.entity-id=https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com
idp.freja.sort-order=1
idp.freja.logo-url=https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com/idp/images/frejaeid_logo.svg
idp.freja.logo-width=75
idp.freja.logo-height=75

idp.refidp.entity-id=https://qa.md.swedenconnect.se/
idp.refidp.sort-order=2
```

### Management API

Somewhat overkill for a test application, but **Test my eID** also has a management API.

Endpoints for monitoring and administering the service can accessed via the management port (default: 8444). This port should not be publicly exposed and is for internal use only. The following endpoints are available:

#### Health - /manage/health

Returns a general health indication for the service. For an "UP" status, the endpoint will return a 200 HTTP status along with a JSON response that may look something like:

```
curl --insecure https://<server>:8444/testmyeid/manage/health

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

#### Info - /manage/info

The `/manage/info` endpoint displays information about the service. Spring Boot supplies some information such as build info and version information.

```
curl --insecure https://<server>:8444/testmyeid/manage/info

{
   "app" : {
      "version" : "1.0.0",
      "name" : "test-my-eid",
      "description" : "Application for testing my eID"
   }
}

```


Copyright &copy; 2016-2018, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

