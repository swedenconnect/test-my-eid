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

### Building

Build the application with Maven:

```bash
mvn clean install
```

This gives `target/test-my-eid-<version>-exec.jar`, the executable jar.

To build a Docker image to your local Docker, use the `local` execution of Jib:

```bash
mvn clean package jib:dockerBuild@local
```

The image is named `local/test-my-eid:<version>` and is built for the architecture of your machine (`linux/amd64` or `linux/arm64`), so it runs without emulation.

### Releases

Released versions are published to Maven Central as `se.swedenconnect.eid:test-my-eid`, and the Docker image is published to `ghcr.io/swedenconnect/test-my-eid`, for `linux/amd64` and `linux/arm64`, tagged with the version and with `latest`. What each version contains is described in the [release notes](release-notes.md).

Releases are made by GitHub workflows when a version tag is pushed. How to make a release is described in [internal/release.md](internal/release.md).

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
| `server.servlet.context-path`<br />`SERVER_SERVLET_CONTEXT_PATH` | The context path for the application | `/` |
| `server.ssl.enabled`<br />`SERVER_SSL_ENABLED` | Is TLS enabled for the application? | `true` |
| `server.ssl.key-store`<br />`SERVER_SSL_KEY_STORE` | The path to the keystore holding the application TLS key and certificate. | - |
| `server.ssl.key-store-type`<br />`SERVER_SSL_KEY_STORE_TYPE` | The type of the TLS keystore (PKCS12/JKS). | - |
| `server.ssl.key-store-password`<br />`SERVER_SSL_KEY_STORE_PASSWORD` | The password for the above keystore. | - |
| `server.ssl.key-alias`<br/>`SERVER_SSL_KEY_ALIAS` | The keystore alias holding the TLS key and certificate. | - |
| `server.ssl.key-password`<br/>`SERVER_SSL_KEY_PASSWORD` | The password to unlock the TLS key. | - |
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
| `sp.federation.metadata.url`<br />`SP_FEDERATION_METADATA_URL` | The URL from which federation metadata is periodically downloaded.<br/>Production: `https://md.swedenconnect.se/role/idp.xml`<br/>QA: `https://qa.md.swedenconnect.se/role/idp.xml`<br/>Sandbox: `https://eid.svelegtest.se/metadata/mdx/role/idp.xml` | - |
| `sp.federation.metadata.`<br />`validation-certificate`<br />`SP_FEDERATION_METADATA_`<br />`VALIDATION_CERTIFICATE` | Path to the certificate that is to be used to verify metadata signatures, for example `file:/opt/testmyeid/sc-metadata.crt`. | - |
| `sp.discovery.`<br/>`static-idp-configuration`<br/>`SP_DISCOVERY_`<br />`STATIC_IDP_CONFIGURATION` | Optional configuration file that tells how the IdP discovery page should be displayed. See further the "IdP Discovery Configuration" section below.<br/>Give the full path prefixed with `file:`. | - |
| `sp.discovery.black-list`<br />`SP_DISCOVERY_BLACK_LIST` | A list of black-listed IdP:s (entity ID:s) | - |
| `sp.discovery.include-only-static`<br />`SP_DISCOVERY_INCLUDE_ONLY_STATIC` | Whether only statically configured IdP:s should be selectable (see above). | `false` |
| `sp.discovery.cache-time`<br />`SP_DISCOVERY_CACHE_TIME` | Number of seconds the application should keep discovery cache. | `600` (10 minutes) |
| `sp.discovery.ignore-contracts`<br />`SP_DISCOVERY_IGNORE_CONTRACTS` | Should contract entity categories be ignored during discovery matching? | `true` |
| `sp.security.algorithm-config.`<br/>`rsa-oaep-digest`<br/>`SP_SECURITY_ALGORITHM_CONFIG_`<br />`RSA_OAEP_DIGEST` | Which digest method to use as default for RSA-OAEP encryption. Consider using `http://www.w3.org/2000/09/xmldsig#sha1` if we run into too many interop issues with the SHA-256 default. | `http://www.w3.org/2001/04/xmlenc#sha256` |
| `sp.security.algorithm-config.`<br/>`use-aes-gcm`<br/>`SP_SECURITY_ALGORITHM_CONFIG_`<br />`USE_AES_GCM` | Should AES-GCM block cipher be used? The alternative is AES-CBC. | `true` |

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
| `protocol` | The protocol of the entry: `saml` for a SAML IdP and `oidc` for an OpenID Provider. See [OpenID Connect](#openid-connect). | `saml` |
| `entity-id` | The entityID of the IdP. | Required for `saml` entries - no default |
| `issuer` | The issuer of the OpenID Provider. | Required for `oidc` entries - no default |
| `display-name-sv`<br />`display-name-en` | The display name in Swedish/English for the IdP. | IdP metadata entry (`mdui:DisplayName` element with language tag "sv"/"en"). |
| `description-sv`<br />`description-en` | For some IdP:s we may want to add additional information. This property provides this information in Swedish/English. | - |
| `logo-url` | An URL for the IdP logotype that should be displayed in the UI. | IdP metadata entry (`mdui:Logo` element with the most "square" dimensions). |
| `logo-width`<br />`logo-height` | The width/height for `logo-url` | - |
| `enabled` | Enable flag. May be used if a configuration for an IdP is set up, but it should not be active until later. | `true` |

The start page lists SAML IdP:s and OpenID Providers in one list. The order of the entries in the configuration file decides the order of the whole list. Entries that are not in the file follow, first the IdP:s and then the OP:s. The `sp.discovery.include-only-static` setting applies to both protocols.

**Example:**

An IdP configuration file for the Sweden Connect QA federation may look like:

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

### OpenID Connect

Besides acting as a SAML SP, **Test my eID** is an OpenID Connect Relying Party (RP), so that users can test OpenID Providers (OP:s) the same way they test SAML IdP:s. There is one RP, used both for authentication and for signature approval.

The RP follows the [OpenID Connect Profile for Sweden Connect](https://docs.swedenconnect.se/technical-framework/updates/OpenID_Connect_Profile_for_Sweden_Connect.html), the [Sweden Connect OpenID Connect Metadata Requirements](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html) and the [Sweden Connect Security Requirements](https://docs.swedenconnect.se/federation/security-requirements.html).

The application starts and works as before without any `rp.*` settings. The RP then uses its defaults, no OP:s are listed, and the entity configuration is still published.

#### RP settings

All settings that only concern OpenID Connect are placed under `rp.*`.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `rp.entity-id` | The entity identifier of the RP. It is also the RP's client ID towards every OP. It must start with the base URI and context path, since the entity configuration is published under it. | `sp.base-uri` plus the servlet context path |
| `rp.credential.sign` | The OIDC signing credential, used for Request Objects and token endpoint assertions. Configured as `sp.credential.sign`, see [Credential Configuration Support](https://docs.swedenconnect.se/credentials-support/#configuration-support). | `sp.credential.sign` |
| `rp.credential.decrypt` | The OIDC decryption credential. | `sp.credential.decrypt` |
| `rp.credential.federation` | The federation entity key that signs the entity configuration. Required when `rp.federation.enabled` is `true`. | The OIDC signing credential (only when federation is disabled) |
| `rp.federation.enabled` | Whether the RP is a member of an OpenID Federation. | `false` |
| `rp.subject-type` | The `subject_type` declared in the RP metadata (`public` or `pairwise`). | `public` |
| `rp.encryption.enabled` | Whether ID tokens and UserInfo responses are to be encrypted. | `false` |
| `rp.encryption.id-token-alg`<br/>`rp.encryption.userinfo-alg` | Key management algorithm for ID tokens/UserInfo responses. Allowed values are `RSA-OAEP`, `RSA-OAEP-256` and `ECDH-ES`, and the value must fit the decryption key. | `RSA-OAEP-256` for an RSA key, `ECDH-ES` for an EC key |
| `rp.encryption.id-token-enc`<br/>`rp.encryption.userinfo-enc` | Content encryption algorithm for ID tokens/UserInfo responses. Allowed values are `A128CBC-HS256`, `A256CBC-HS512`, `A128GCM` and `A256GCM`. | `A256GCM` |
| `rp.entity-configuration-lifetime` | The lifetime of the signed entity configuration. | `7d` |
| `rp.metadata.*` | Overrides for the RP metadata values, see below. | - |
| `rp.providers` | Manually configured OP:s, see below. | - |
| `rp.discovery.refresh-interval` | How often the discovery documents of manually configured OP:s are fetched. | `1h` |
| `rp.discovery.retry-interval` | How soon a failed fetch is retried. | `5m` |
| `rp.discovery.black-list` | Issuers of OP:s that should not be listed. The SAML setting `sp.discovery.black-list` does not apply to OP:s. | - |
| `rp.cancel-terms` | Terms that, when found in the `error_description` of an `access_denied` error response, mean that the user cancelled. The match is a case-insensitive substring match, and the user is then returned to the start page. | `cancel`, `cancelled`, `canceled`, `abort`, `aborted`, `avbryt`, `avbruten`, `avbrutet`, `avbröt`, `avbrutit` |
| `rp.plain-user-message-template.<lang>` | Plain-text user message templates, see below. | `classpath:user-message-plain_sv.txt` and `classpath:user-message-plain_en.txt` |

Startup fails with a message telling what is wrong if federation is enabled without a federation key, if encryption is turned on with a disallowed algorithm or without a decryption credential, or if the RP metadata would miss a value that the Sweden Connect requirements make mandatory.

#### RP metadata

The application builds the RP metadata itself, so that it always meets the Sweden Connect requirements:

- `redirect_uris` holds one redirect URI, `/oidc/callback` under the base URI and context path. It is used both for authentication and signature approval.
- `response_types` is `["code"]`, `grant_types` is `["authorization_code"]` and `token_endpoint_auth_method` is `private_key_jwt`.
- The keys are given by value in `jwks`. The set holds the OIDC signing key, and the decryption key when encryption is turned on. Every key has a `kid`.
- `request_object_signing_alg` and `token_endpoint_auth_signing_alg` are given by the signing key: `RS512` for an RSA key, and `ES256`, `ES384` or `ES512` for an EC key on P-256, P-384 or P-521.
- `id_token_signed_response_alg` and `userinfo_signed_response_alg` are not declared, see Section 4.1 of the metadata requirements.
- When encryption is turned on, `id_token_encrypted_response_alg`/`_enc` and `userinfo_encrypted_response_alg`/`_enc` are declared.

The descriptive values are taken from the SAML metadata settings, and each one can be overridden:

| Metadata parameter | Taken from | Override |
| :--- | :--- | :--- |
| `client_name#sv`, `client_name#en` | `sp.metadata.service-names` | `rp.metadata.client-names` (for example `sv-Testa ditt eID`) |
| `logo_uri` | The first logo under `sp.metadata.uiinfo.logos`, made an absolute URL with the base URI | `rp.metadata.logo-uri` |
| `client_uri` | The start page of the application | `rp.metadata.client-uri` |
| `contacts` | The email addresses of the support and technical contact persons under `sp.metadata.contact-persons` | `rp.metadata.contacts` |
| `organization_name#sv`, `organization_name#en` | `sp.metadata.organization.names` | `rp.metadata.organization-names` |
| `organization_identifier` | `urn:glue:iso6523:0007:<number>` where the number is `sp.metadata.organization.number`. Left out when the number is not ten digits. | `rp.metadata.organization-identifier` |

`client_name` must be given in both Swedish and English, and `logo_uri` and `client_uri` must be HTTPS URL:s.

#### Entity configuration and /oidc/metadata

The RP's OpenID Federation entity configuration is always published at `<entity identifier>/.well-known/openid-federation`, also when federation is disabled. It is signed with the federation key and holds the RP metadata under `openid_relying_party`. A signed entity configuration is reused until half of its lifetime has passed, or until its content changes.

The `metadata` claim of the entity configuration is also published as JSON at `/oidc/metadata`. Operators of manually configured OP:s use this document to register the RP.

#### Manually configured OP:s

OP:s are configured as a list under `rp.providers`:

| Property | Description |
| :--- | :--- |
| `issuer` | The issuer identifier of the OP. Required. |
| `discovery-document` | The OP's discovery document given inline as JSON (optional). |
| `discovery-document-resource` | A resource holding the OP's discovery document, for example `file:/opt/testmyeid/op.json` (optional). |

When the discovery document is given, nothing is fetched for that OP. Otherwise the document is fetched from `<issuer>/.well-known/openid-configuration`, and a document whose `issuer` does not equal the configured issuer is rejected. Documents are fetched in the background and refreshed according to `rp.discovery.refresh-interval`. An OP without a document is left out of the start page (and logged), and a failed refresh keeps the last fetched document. A failing OP never stops startup.

The operator of the OP must register the RP with the client ID given by `rp.entity-id` and the metadata published at `/oidc/metadata`. The RP authenticates at the token endpoint with `private_key_jwt`.

Example:

```
rp:
  providers:
    - issuer: https://op.example.com
    - issuer: https://other-op.example.com
      discovery-document-resource: file:/opt/testmyeid/other-op.json
```

#### OP:s on the start page

Every listed OP is shown on the start page, marked as OpenID Connect. Its name, description and logo are taken from the `display_name`, `description` and `logo_uri` parameters of its metadata (with language tags where present). The issuer is used as name when the metadata holds no name.

OP:s can be renamed, reordered and disabled in the IdP discovery configuration file using entries with `protocol: oidc` (see [IdP Discovery Configuration](#idp-discovery-configuration)):

```
idp:
  - protocol: oidc
    issuer: https://op.example.com
    display-name-sv: Mitt OP
    display-name-en: My OP
  - entity-id: http://qa.test.swedenconnect.se/idp
```

#### Authentication

When the user selects an OP, an authentication request is sent to its authorization endpoint by an automatically submitted form (HTTP POST). The authorization code flow is used, and all parameters are carried in a Request Object passed by value in the `request` parameter. The Request Object is signed with the RP's OIDC signing key, its `iss` is the client ID and its `aud` is the OP's issuer. The `response_type`, `client_id` and `scope` parameters, which OpenID Connect Core requires outside the Request Object, are also sent as plain parameters.

The request contains:

- `scope` – `openid` plus `https://id.oidc.se/scope/naturalPersonInfo` and `https://id.oidc.se/scope/naturalPersonNumber` when the OP lists them in `scopes_supported`.
- `prompt=login` – so that the user always authenticates, as the Sweden Connect profile recommends.
- `acr_values` – every value in the OP's `acr_values_supported`. Left out when the OP lists none.
- `state`, `nonce` and PKCE (`S256`) – always. `state` is tied to the user's session.
- `redirect_uri` – the RP's single redirect URI.
- `https://id.oidc.se/param/userMessage` – a notice that this is a test authentication, sent only when the OP declares `https://id.oidc.se/disco/userMessageSupported`. If the OP lists `text/markdown` in `https://id.oidc.se/disco/userMessageSupportedMimeTypes`, the Markdown templates of `sp.ui.user-message-template` are used. Otherwise the plain-text templates of `rp.plain-user-message-template` are sent as `text/plain`.

The code is exchanged at the token endpoint with `private_key_jwt` client authentication (a new assertion for every call, with the token endpoint as audience) and the PKCE code verifier. The ID token is validated as OpenID Connect Core requires (signature, `iss`, `aud`, expiry, `nonce` and presence of `auth_time`), and only the signature algorithms allowed by the Sweden Connect security requirements are accepted. UserInfo is then always called, and its response must be signed. Its `sub` must equal the `sub` of the ID token. When encryption is turned on, both the ID token and the UserInfo response must be encrypted.

If the user cancels (an `access_denied` error whose description holds one of the `rp.cancel-terms`), the user is returned to the start page. Other error responses are shown on an error page with the `error` and `error_description` values. A `state` that does not match, or a failed validation, ends on the application error page.

#### Claims on the result page

The claims from the ID token and UserInfo are merged and shown on the result page the same way SAML attributes are shown. A claim is shown with the label of the SAML attribute that has the claim name in its `claim-name` setting in `sp.ui.attributes`, for example:

```
sp:
  ui:
    attributes:
      - attribute-name: urn:oid:1.2.752.29.4.13
        claim-name: https://id.oidc.se/claim/personalIdentityNumber
        message-code: sp.msg.attr.personal-id-number.name
```

An entry may also have only a `claim-name`, for claims that have no SAML counterpart (as `https://id.oidc.se/claim/coordinationNumber`). Claims without a configured label are left out. The `acr` value is shown with the same texts as the SAML LoA URI:s.

#### Signature approval

After a successful OIDC authentication, the result page offers a signature step when the OP lists `https://id.oidc.se/scope/signApproval` in `scopes_supported`. This is the "signature approval" use case of the [Signature Extension for OpenID Connect](https://www.oidc.se/specifications/oidc-signature-extension-1_1.html). The same RP and redirect URI are used as for authentication.

The request is built as the authentication request, with these differences:

- `scope` – `openid`, `https://id.oidc.se/scope/signApproval` and the same identity scopes as for authentication.
- `prompt` – both `login` and `consent`.
- `https://id.oidc.se/param/signRequest` – holds a `sign_message` (the test sign message, as `text/plain`) and no `tbs_data`.
- `claims` – binds the request to the authenticated user. Under `id_token`, the personal identity number (or the coordination number when that was what the authentication delivered) is requested as essential with its value, and `acr` is requested as essential with the value received in the authentication.
- No `acr_values`, since `acr` is requested in `claims`.

The response is processed as for authentication. The identity in the response must match the stored authentication, otherwise the application error page is shown. A signature approval never replaces the stored authentication.

#### OpenID Federation

With `rp.federation.enabled` set to `true`, the RP is a member of an OpenID Federation: its entity configuration gets `authority_hints` and the RP's own trust marks, OP:s are found and resolved through the federation, and the `acr` that an OP issues is checked against the OP's Level of Assurance trust marks. Nothing of this happens when federation is disabled. In particular, no listing, resolving or trust mark fetching is made.

When federation is enabled, the RP metadata also declares `client_registration_types` `["automatic"]`. Requests to OP:s found through the federation use automatic registration with the RP's entity identifier as client ID, and the Request Objects meet the requirements of Section 12.1.1.1 of OpenID Federation (`aud` is the OP's entity identifier only, `iss` and `client_id` are the RP's entity identifier, no `sub`, and `jti` and `exp` are always present). Authentication and signature approval work the same for these OP:s as for manually configured ones.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `rp.federation.enabled` | Whether the RP is a member of an OpenID Federation. | `false` |
| `rp.credential.federation` | The federation entity key that signs the entity configuration. Required when federation is enabled. | - |
| `rp.federation.trust-anchor.entity-id` | The entity identifier of the trust anchor. Required when federation is enabled. | - |
| `rp.federation.trust-anchor.jwks`<br/>`rp.federation.trust-anchor.jwks-resource` | The trust anchor's federation key(s), given as a JWK or a JWK set (JSON), inline or as a resource. One of them is required when federation is enabled. The trust anchor's self-declared keys are never trusted on their own. | - |
| `rp.federation.trust-anchor.resolve-endpoint` | The resolve endpoint of the trust anchor. | The `federation_resolve_endpoint` of the trust anchor's entity configuration, verified with the configured key |
| `rp.federation.listing-sources[].entity-id` | The entities whose subordinate listing endpoints are asked for OP:s. In Sweden Connect this is normally the OP registration intermediate. | The trust anchor |
| `rp.federation.listing-sources[].list-endpoint` | The listing endpoint of the source. | The `federation_list_endpoint` of the source's metadata |
| `rp.federation.authority-hints` | The `authority_hints` of the RP's entity configuration. In Sweden Connect, the RP registration intermediate. | - |
| `rp.federation.trust-mark-issuers[].entity-id` | The entity identifier of an issuer of the RP's trust marks. | - |
| `rp.federation.trust-mark-issuers[].trust-mark-endpoint` | The issuer's trust mark endpoint. | The `federation_trust_mark_endpoint` of the issuer's metadata |
| `rp.federation.trust-mark-issuers[].trust-mark-types` | The trust mark types to request from the issuer for the RP. | - |
| `rp.federation.refresh-interval` | How often OP:s are listed and resolved, and the RP's trust marks are checked for renewal. | `1h` |
| `rp.federation.retry-interval` | How soon a failed listing, resolve or trust mark fetch is retried. | `5m` |
| `rp.federation.loa-trust-marks` | The mapping used for the LoA trust mark check, see below. | See below |

Startup fails if federation is enabled without a trust anchor key or a federation key.

**Sweden Connect values**

The values below are taken from [Sweden Connect - OpenID Federation Structure](https://docs.swedenconnect.se/federation/oidf-structure.html), which also publishes the trust anchor keys.

| Setting | Sandbox | QA | Production |
| :--- | :--- | :--- | :--- |
| `trust-anchor.entity-id` | `https://fed.sandbox.swedenconnect.se/trustanchor` | `https://qa.fed.swedenconnect.se/trustanchor` | `https://fed.swedenconnect.se/trustanchor` |
| `listing-sources[0].entity-id` (OP registration intermediate) | `https://fed.sandbox.swedenconnect.se/im-reg-sc-op` | `https://qa.fed.swedenconnect.se/im-reg-sc-op` | `https://fed.swedenconnect.se/im-reg-sc-op` |
| `authority-hints` (RP registration intermediate) | `https://fed.sandbox.swedenconnect.se/im-reg-sc` | `https://qa.fed.swedenconnect.se/im-reg-sc` | `https://fed.swedenconnect.se/im-reg-sc` |
| Contracts trust mark issuer | `https://fed.sandbox.swedenconnect.se/tmi-contracts` | `https://qa.fed.swedenconnect.se/tmi-contracts` | `https://fed.swedenconnect.se/tmi-contracts` |

Example (QA):

```
rp:
  credential:
    federation:
      jks:
        store:
          location: file:/opt/testmyeid/federation.jks
          password: secret
          type: JKS
        key:
          alias: federation
          key-password: secret
  federation:
    enabled: true
    trust-anchor:
      entity-id: https://qa.fed.swedenconnect.se/trustanchor
      jwks-resource: file:/opt/testmyeid/qa-trust-anchor-jwks.json
    listing-sources:
      - entity-id: https://qa.fed.swedenconnect.se/im-reg-sc-op
    authority-hints:
      - https://qa.fed.swedenconnect.se/im-reg-sc
    trust-mark-issuers:
      - entity-id: https://qa.fed.swedenconnect.se/tmi-contracts
        trust-mark-types:
          - https://id.swedenconnect.se/contract/sc/prepaid-auth-2021
```

**The RP's trust marks**

For every configured trust mark type, the trust mark is requested from the issuer's trust mark endpoint for the RP's entity identifier. A fetched mark is verified (its signature with the issuer's keys obtained through the trust anchor, its `sub` and its type) before it is published in the entity configuration. Marks are renewed before they expire. A failed fetch keeps the current mark until it expires and is retried; it never stops the service or withholds the entity configuration. A change in the trust marks or authority hints makes the entity configuration be signed anew.

**How OP:s are found**

Each listing source is asked for entities of type `openid_provider`, and every OP found is resolved through the trust anchor's resolve endpoint. The resolve response is verified with the trust anchor key. The resolved `openid_provider` metadata is used as the OP's discovery document, and its display name and logo are shown on the start page.

Listing and resolving run at `rp.federation.refresh-interval`, and a failed resolve is retried after `rp.federation.retry-interval`. Resolved metadata is used until the next refresh or until the resolve response expires, whichever comes first. An OP whose resolve response has expired without a new resolve leaves the list.

An issuer that is both configured manually (under `rp.providers`) and found in the federation is shown once, from the manual configuration. Removing the manual entry brings the federation entry back at the next refresh. The OP black list (`rp.discovery.black-list`) and the IdP discovery configuration file apply to OP:s found through the federation too.

**Level of Assurance trust mark check**

After an authentication or signature approval at an OP found through the federation, the `acr` in the ID token is checked against the LoA trust marks in the OP's resolve response. When the OP lacks a trust mark that the `acr` needs, the result page shows a warning, but the flow is not stopped. No check is made for manually configured OP:s.

The mapping is given by `rp.federation.loa-trust-marks`, a list of rules where each rule has a list of `acr` values and the trust mark types that an OP issuing one of them must hold (all of them). An `acr` that no rule covers needs no trust mark (for example the `uncertified-*` URI:s and `loa1`). The default rules are:

| `acr` | Required trust marks |
| :--- | :--- |
| `http://id.elegnamnden.se/loa/1.0/loa2` | `https://id.swedenconnect.se/loa/loa2` |
| `http://id.elegnamnden.se/loa/1.0/loa3` | `https://id.swedenconnect.se/loa/loa3` |
| `http://id.elegnamnden.se/loa/1.0/loa4` | `https://id.swedenconnect.se/loa/loa4` |
| `http://id.swedenconnect.se/loa/1.0/loa2-nonresident` | `https://id.swedenconnect.se/loa/nonresident` and `https://id.swedenconnect.se/loa/loa2` |
| `http://id.swedenconnect.se/loa/1.0/loa3-nonresident` | `https://id.swedenconnect.se/loa/nonresident` and `https://id.swedenconnect.se/loa/loa3` |
| `http://id.swedenconnect.se/loa/1.0/loa4-nonresident` | `https://id.swedenconnect.se/loa/nonresident` and `https://id.swedenconnect.se/loa/loa4` |
| `http://id.elegnamnden.se/loa/1.0/eidas-low`, `eidas-nf-low`, `eidas-sub`, `eidas-nf-sub`, `eidas-high`, `eidas-nf-high` | `https://id.swedenconnect.se/loa/eidas` |

Setting `rp.federation.loa-trust-marks` replaces all default rules, for example:

```
rp:
  federation:
    loa-trust-marks:
      - acr:
          - http://id.elegnamnden.se/loa/1.0/loa3
        trust-marks:
          - https://id.swedenconnect.se/loa/loa3
      - acr:
          - http://id.swedenconnect.se/loa/1.0/loa3-nonresident
        trust-marks:
          - https://id.swedenconnect.se/loa/nonresident
          - https://id.swedenconnect.se/loa/loa3
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


Copyright &copy; 2016-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
