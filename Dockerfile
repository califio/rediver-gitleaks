FROM golang:1.25-bookworm AS build
# install dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git \
    tzdata \
    ssh \
    ca-certificates \
    build-essential

WORKDIR /go/src/app
ENV CGO_ENABLED=0 GOOS=linux
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-X main.Version=${VERSION}" -o /go/bin/rediver-gitleaks

FROM bitnami/minideb:bookworm AS final
RUN install_packages \
      git \
      curl \
      ca-certificates

WORKDIR /app
# copy pre-built go applications
COPY --from=build /go/bin /usr/bin
ENTRYPOINT ["/usr/bin/rediver-gitleaks"]
