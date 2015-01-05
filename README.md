Duo-in-WSO2-IS
==============

Build Provisioning connector and copy the jar in IS_HOME/repository/components/dropings

Build Authenticator and copy the jar in IS_HOME/repository/components/dropings

Build Endpoint and deploy in IS_HOME/repository/deployments/server/webapps

Buid mgt_ui and copy the jar into a new patch folder in IS_HOME/repository/components/patches

This implementation needs 2 additional libraries from Duo, which can be found in following 2 links

https://github.com/duosecurity/duo_client_java   - build duo-client and add jar file in IS_HOME/repository/components/lib

https://github.com/duosecurity/duo_java  - build and add jar file in IS_HOME/repository/components/lib

*Developed in WSO2 IS 5.0.0

