# ═══════════════════════════════════════════════════════════════════════════════
# SBI EMS — Hardened Multi-Stage Dockerfile
# DevSecOps Training | Day 2: Container Security
#

# DevSecOps fixes vs. the "Insecure Dockerfile" shown in the courseware:
#  BEFORE (insecure — from courseware Module 6):
#    FROM openjdk:17-jdk          ← full JDK (600MB+), running as ROOT
#    COPY target/*.jar app.jar
#    ENTRYPOINT ["java", "-jar", "app.jar"]
#    Problems: root user, full JDK attack surface, no health check, no layers
#
#  AFTER (this file):
#    ✅ Multi-stage: build in JDK, run in JRE-only (smaller attack surface)
#    ✅ Non-root user (emsuser) — limits blast radius if exploited
#    ✅ Alpine base — minimal OS packages = fewer CVEs
#    ✅ Layer caching — dependencies layer cached separately from source
#    ✅ HEALTHCHECK — Kubernetes/Docker uses this for readiness
#    ✅ JVM tuned for containers — prevents memory over-allocation
#    ✅ No secrets in ENV — all injected at runtime via docker-compose or K8s
#
# Scan this image:
#   trivy image ems:latest
#   docker scout quickview ems:latest
# ═══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Build (Maven + JDK — used only at build time) ───────────────────
FROM maven:3.9-eclipse-temurin-21-alpine AS build

LABEL stage="builder"

WORKDIR /workspace

# Copy dependency descriptor first — Docker caches this layer separately.
# If only source changes (not pom.xml), dependencies are not re-downloaded.
COPY pom.xml .

# Download dependencies in isolation — this layer is cached between builds
# as long as pom.xml does not change (major time saver in CI/CD).
RUN mvn dependency:go-offline -q 2>/dev/null || true

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests -q

# ── Stage 2: Runtime (JRE only — much smaller, fewer CVEs) ───────────────────
FROM eclipse-temurin:21-jre-alpine

# DevSecOps: Add labels for image provenance and scanning identification
LABEL org.opencontainers.image.title="SBI EMS API" \
      org.opencontainers.image.description="Employee Management System — DevSecOps Training" \
      org.opencontainers.image.vendor="State Bank of India" \
      org.opencontainers.image.version="1.0.0"

# DevSecOps: Create a dedicated non-root user.
# If an attacker exploits a bug in the app, they get emsuser privileges
# (limited to /app), NOT root privileges on the host.
RUN addgroup -S emsgroup \
 && adduser  -S emsuser -G emsgroup

WORKDIR /app

# Copy ONLY the compiled JAR from the build stage — not source, not Maven cache
COPY --from=build /workspace/target/ems-*.jar app.jar

# Create logs directory with correct ownership
RUN mkdir -p /app/logs && chown -R emsuser:emsgroup /app

# Switch to non-root user — from this point, all commands run as emsuser
USER emsuser

# Expose only the application port
EXPOSE 8080

# DevSecOps: Health check — Docker and Kubernetes use this to determine
# whether the container is healthy before routing traffic to it.
HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=60s \
            --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health | grep -q '"status":"UP"' || exit 1

# DevSecOps: JVM tuned for container environments.
#   -XX:+UseContainerSupport       → reads cgroup memory limits (not host RAM)
#   -XX:MaxRAMPercentage=75.0      → use max 75% of container memory for heap
#   -Djava.security.egd=file:/dev/./urandom → faster SecureRandom (avoids /dev/random blocking)
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
