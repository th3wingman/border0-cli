FROM --platform=$BUILDPLATFORM alpine
ARG TARGETOS TARGETARCH
ADD https://download.border0.com/linux_$TARGETARCH/border0 /border0
RUN chmod ogu+x /border0
CMD ["border0"]


