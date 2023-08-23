#!/bin/bash
docker build -t rpm-builder -f .github/docker/Dockerfile .

docker run -ti --rm \
    -v $PWD/bin:/root/bin \
    -v $PWD/rpm:/root/rpm \
    --env FILE_ARCH="amd64" \
    --env PGP_PRIVATE_KEY="$(gpg --armor --export-secret-keys support@border0.com)" \
    --env BORDER0_VERSION="$(git describe --long --tags)" \
    rpm-builder
