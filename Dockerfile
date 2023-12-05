FROM openjdk:18.0.2.1-slim

LABEL org.opencontainers.image.source=https://github.com/swedenconnect/test-my-eid
LABEL org.opencontainers.image.description="Sweden Connect Test my eID"
LABEL org.opencontainers.image.licenses=Apache-2.0

ADD target/test-my-eid-*-exec.jar /test-my-eid.jar

ENV JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED -Djava.net.preferIPv4Stack=true -Dorg.apache.xml.security.ignoreLineBreaks=true"

ENTRYPOINT exec java $JAVA_OPTS -jar /test-my-eid.jar

EXPOSE 8443 8444 8009
