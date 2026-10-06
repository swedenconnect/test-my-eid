![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# Release Notes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

### Version 4.0.0

**Date:** 2026-10-06

- Test my eID is now also an OpenID Connect Relying Party. OpenID Providers are shown next to the SAML Identity Providers on the start page, and both authentication and signature approval are supported, following the Swedish OpenID Connect profiles.
- Support for OpenID Federation. The Relying Party publishes an entity configuration with trust marks, and OpenID Providers can be found and trusted through the federation's trust anchor.
- Fixed the cache of the SAML Identity Provider list. The list is now kept for the configured cache time, instead of being rebuilt on every request at first and then never again.
- The Docker image now runs on Java 25.
- Upgraded to Spring Boot 4.1.1, OpenSAML 5.2.3 and Bouncy Castle 1.86, together with other dependency upgrades.

-----

Copyright &copy; 2016-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
