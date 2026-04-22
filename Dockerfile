# syntax=docker/dockerfile:1.7

FROM maven:3.9.11-eclipse-temurin-25 AS build
WORKDIR /workspace

COPY pom.xml .
RUN --mount=type=secret,id=maven_settings,target=/root/.m2/settings.xml \
	--mount=type=secret,id=maven_security,target=/root/.m2/settings-security.xml \
	mvn -B -ntp -DskipTests dependency:go-offline

COPY src src
RUN --mount=type=secret,id=maven_settings,target=/root/.m2/settings.xml \
	--mount=type=secret,id=maven_security,target=/root/.m2/settings-security.xml \
	mvn -B -ntp -DskipTests package

FROM dhi.io/eclipse-temurin:25-debian13
WORKDIR /app
COPY --from=build /workspace/target/*.jar app.jar
USER nonroot
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "app.jar"]
