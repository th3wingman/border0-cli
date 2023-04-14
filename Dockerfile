# FROM --platform=$BUILDPLATFORM alpine
FROM scratch
ARG TARGETOS TARGETARCH
ENV UMASK=022
ADD https://download.border0.com/${TARGETOS}_${TARGETARCH}/border0 /border0
ENV UMASK=177
#COPY ./bin/mysocketctl_$TARGETOS_$TARGETARCH /border0
# RUN chmod ogu+x /border0
ENTRYPOINT [ "/border0" ]
CMD ["help"]
