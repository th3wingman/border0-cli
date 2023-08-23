FROM quay.io/centos/centos:stream9

# Install necessary tools
RUN yum install -y gnupg rpm-build rpm-sign rpmdevtools createrepo


# The directory where we'll map the binary
WORKDIR /

# Copy scripts from repository into the Docker container
COPY ./build-rpm.sh /
COPY ./generate-rpm-repo.sh /

# Ensure the scripts are executable
RUN chmod +x /build-rpm.sh /generate-rpm-repo.sh

# Run multiple scripts or commands
CMD sh -c "/build-rpm.sh && /generate-rpm-repo.sh"


