FROM openjdk:18.0.2.1-slim

ADD target/test-my-eid-*-exec.jar /test-my-eid.jar

ENV JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED -Djava.net.preferIPv4Stack=true -Dorg.apache.xml.security.ignoreLineBreaks=true"

ENTRYPOINT exec java $JAVA_OPTS -jar /test-my-eid.jar

EXPOSE 8443 8444 8009
