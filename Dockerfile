# syntax=docker/dockerfile:1.7

FROM eclipse-temurin:26-jdk AS build
WORKDIR /workspace

# Copy Gradle wrapper and build metadata first to maximize layer caching.
COPY gradlew gradlew.bat settings.gradle build.gradle ./
COPY gradle gradle
RUN chmod +x gradlew

# Copy source and build the Spring Boot executable jar.
COPY src src
RUN ./gradlew --no-daemon clean bootJar

FROM eclipse-temurin:26-jre AS runtime
WORKDIR /app

# Copy the built jar. This project produces a single bootJar artifact.
COPY --from=build /workspace/build/libs/*.jar /app/app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]

