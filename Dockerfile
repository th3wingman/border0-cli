FROM --platform=$TARGETPLATFORM alpine
ARG TARGETOS TARGETARCH
COPY ./bin/border0_${TARGETOS}_${TARGETARCH} /border0
RUN chmod ogu+x /border0
RUN echo -e "Welcome to Border0 Connector.\nVisit <https://border0.com/> for more details.\n\nLooking for support? We're here to help! \nDocumentation: <https://docs.border0.com/>\nGetitng in touch: <https://docs.border0.com/docs/getting-help/>\nE-mail: support@border0.com\n\n" > /etc/motd

ARG BORDER0_VERSION
LABEL org.opencontainers.image.description "Border0 CLI Tooll version: ${BORDER0_VERSION}"

ENTRYPOINT [ "/border0" ]
CMD ["help"]
