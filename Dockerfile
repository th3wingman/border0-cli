FROM --platform=$BUILDPLATFORM alpine
ARG TARGETOS TARGETARCH
ADD https://download.border0.com/linux_$TARGETARCH/border0 /usr/local/bin/border0
RUN chmod ogu+x /usr/local/bin/border0
CMD ["border0"]


