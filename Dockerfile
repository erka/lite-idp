FROM golang:1-alpine
ENV CGO_ENABLED=0
ARG TARGETOS TARGETARCH TARGETVARIANT

RUN apk add --no-cache git
COPY . /go/src/github.com/amdonov/lite-idp
WORKDIR /go/src/github.com/amdonov/lite-idp
RUN \
    if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
      export GOARM="${TARGETVARIANT#v}"; \
    fi; \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build -a -mod='vendor' -trimpath='true' -buildvcs='true' -buildmode='exe' -compiler='gc' -o lite-idp

FROM alpine
COPY --from=0 /go/src/github.com/amdonov/lite-idp/lite-idp /usr/bin/lite-idp
EXPOSE 9443
ENTRYPOINT ["lite-idp"]
CMD ["serve"]
