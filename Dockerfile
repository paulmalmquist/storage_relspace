# syntax=docker/dockerfile:1.7
#
# Two build flavors:
#
#   docker build -t strongbox:dev .
#       Fast developer image. Uses prebuilt wheels, whose bundled OpenSSL is NOT FIPS-validated.
#
#   docker build --build-arg FIPS=true --build-arg BASE_IMAGE=<FIPS base> -t strongbox:fips .
#       Production image for CUI. BASE_IMAGE must ship an OpenSSL whose FIPS provider holds a CMVP
#       certificate and is enabled (for example a UBI 9 based Python image built in FIPS mode, or a
#       vendor FIPS Python image). With FIPS=true, `cryptography` and `psycopg` are compiled against
#       that system OpenSSL instead of using wheels with their own bundled copies. The container then
#       refuses to start unless `strongbox fips-check` passes (STRONGBOX_REQUIRE_FIPS=true).
#
ARG BASE_IMAGE=python:3.12-slim

FROM ${BASE_IMAGE} AS build
ARG FIPS=false
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY pyproject.toml README.md ./
COPY src ./src
RUN if [ "$FIPS" = "true" ]; then \
      pip install --no-binary cryptography,psycopg ".[gcp,mcp]" "psycopg[c]" ; \
    else \
      pip install ".[gcp,mcp]" ; \
    fi

FROM ${BASE_IMAGE}
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin strongbox \
 && mkdir -p /data && chown 10001 /data
COPY --from=build /opt/venv /opt/venv
USER 10001
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["strongbox"]
CMD ["serve", "--port", "8080"]
