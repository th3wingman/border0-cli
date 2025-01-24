# Use Alpine as the base platform
FROM alpine

# inset the border0 binary
ARG TARGETOS TARGETARCH
COPY ./bin/border0_${TARGETOS}_${TARGETARCH} /border0

# Install required packages, set permissions and create motd
RUN apk add --no-cache ca-certificates sudo iptables iproute2 && \
    update-ca-certificates && \
    chmod +x /border0 && \
    echo -e "Welcome to Border0 Connector.\nVisit <https://border0.com/> for more details.\n\nLooking for support? We're here to help! \nDocumentation: <https://docs.border0.com/>\nGetitng in touch: <https://docs.border0.com/docs/getting-help/>\nE-mail: support@border0.com\n\n" > /etc/motd

# Set entrypoint and default command
ENTRYPOINT [ "/border0" ]
CMD ["help"]
