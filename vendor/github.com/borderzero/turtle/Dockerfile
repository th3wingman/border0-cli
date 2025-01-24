# Dockerfile
FROM alpine:3.20

COPY server_ws /server_ws

# Install required packages
RUN apk --no-cache add ca-certificates && \
    chmod +x /server_ws

# Expose port 80
EXPOSE 80

# Set the entrypoint to run the WebSocket server
CMD ["/server_ws"]
