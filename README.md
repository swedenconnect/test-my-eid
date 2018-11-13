![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# test-my-eid

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Test application for testing authentication against Identity Providers in the federation.

---

The **Test my eID** Spring Boot application is the official test service provider for testing authentication against the identity providers of the Sweden Connect-federation. 

It is released as open source so that anyone can see how an authentication request that is compliant with the [Sweden Connect Technical Framework](https://docs.swedenconnect.se/technical-framework/) should be constructed. The application also contains a reference for how to validate a response message containing an SAML assertion.

**Test my eID** is available in the following federations:

* Sweden Connect Sandbox - [https://eid.idsec.se/testmyeid](https://eid.idsec.se/testmyeid)

	* Note: Not all IdP:s in the sandbox federation is functioning correctly. The Test my eID-application is currently configured to support all IdP:s that seem to be "up". Anyone adding a new IdP to the sandbox-federation and wants that to be supported by the test application should send a mail to [info@idsec.se](mailto:info@idsec.se).

* Sweden Connect QA - *To be added*

* Sweden Connect Production - *To be added*

Copyright &copy; 2016-2018, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

