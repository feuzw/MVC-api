# 1단계: 빌드
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app
COPY . .

# Gradle 캐시 정리 및 빌드 (재시도 로직 포함)
RUN chmod +x gradlew && \
    ./gradlew clean --no-daemon || true && \
    ./gradlew build -x test --no-daemon --refresh-dependencies || \
    (sleep 5 && ./gradlew build -x test --no-daemon --refresh-dependencies)

# 2단계: 실행
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/build/libs/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
