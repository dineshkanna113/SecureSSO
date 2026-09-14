# AccessHub Multi-Tenant IAM Platform Dockerfile
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app

# Copy Maven wrapper & pom.xml
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Download dependencies
RUN ./mvnw dependency:go-offline -B

# Copy source code and build package
COPY src src
RUN ./mvnw clean package -DskipTests

# Production Runtime Stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
VOLUME /tmp

# Copy compiled jar from build stage
COPY --from=build /app/target/accesshub-iam-1.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
