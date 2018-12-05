FROM openjdk:11-jre

VOLUME /etc/test-my-eid
RUN mkdir /opt/test-my-eid
ADD target/test-my-eid-*.jar /opt/test-my-eid/test-my-eid.jar

ENV JAVA_OPTS="-Djava.security.egd=file:/cfg/./urandom -Dserver.port=8443 -Dserver.ssl.enabled=true -Dmanagement.server.port=8444 -Djava.net.preferIPv4Stack=true"
  
ENTRYPOINT exec java $JAVA_OPTS -jar /opt/test-my-eid/test-my-eid.jar

EXPOSE 8443 8444 8009
