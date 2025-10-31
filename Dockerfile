# Step 1: Use an official JDK base image
FROM eclipse-temurin:17-jdk

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the built jar from the local target folder to the container
COPY target/ssolog-0.0.1-SNAPSHOT.jar app.jar

# Step 4: Expose port 8080 (Spring Boot default)
EXPOSE 8080

# Step 5: Command to run the jar
ENTRYPOINT ["java", "-jar", "app.jar"]
