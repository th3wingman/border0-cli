#!/bin/sh
set -e
apt-ftparchive -c release.conf release repos/dists/stable > repos/dists/stable/Release

echo "Signing the release..."
# cat /pgp-key.private | gpg --import # this step is performed by other task in GH Actions
cat repos/dists/stable/Release | gpg --local-user BBECB4C2D2872160 -abs > repos/dists/stable/Release.gpg
cat repos/dists/stable/Release | gpg --local-user BBECB4C2D2872160 -abs --clearsign > repos/dists/stable/InRelease

echo "Generating public key..."
gpg --local-user BBECB4C2D2872160 --armor --export --output repos/gpg

echo -e "Done!\nAll files are in repos/dists/stable/\n"
