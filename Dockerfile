# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --prefix=/install .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="threatlens" \
      org.opencontainers.image.description="AI-assisted OSINT for defenders"
RUN useradd --create-home --uid 10001 analyst
COPY --from=build /install /usr/local
USER analyst
WORKDIR /home/analyst
# Ollama on the host by default; docker-compose overrides this to the ollama service
ENV OLLAMA_URL=http://host.docker.internal:11434 \
    THREATLENS_CACHE=/home/analyst/.cache/threatlens/cache.sqlite
ENTRYPOINT ["threatlens"]
CMD ["--help"]
