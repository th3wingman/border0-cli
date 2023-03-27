FROM --platform=$BUILDPLATFORM alpine
ARG TARGETOS TARGETARCH
COPY ./bin/mysocketctl_${TARGETOS}_${TARGETARCH} /border0
RUN chmod ogu+x /border0
ENTRYPOINT [ "/border0" ]
CMD ["help"]
