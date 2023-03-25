FROM --platform=$BUILDPLATFORM alpine
ARG TARGETOS TARGETARCH
COPY ./bin/mysocketctl_${TARGETOS}_${TARGETARCH} /usr/local/bin/border0
RUN chmod ogu+x /usr/local/bin/border0
CMD ["border0", "version", "show"]
