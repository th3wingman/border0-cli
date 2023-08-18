#!/bin/sh
set -e
apt-ftparchive -c release.conf release deb/dists/stable > deb/dists/stable/Release

echo "Signing the release..."
# cat /pgp-key.private | gpg --import # this step is performed by other task in GH Actions
cat deb/dists/stable/Release | gpg --local-user BBECB4C2D2872160 -abs > deb/dists/stable/Release.gpg
cat deb/dists/stable/Release | gpg --local-user BBECB4C2D2872160 -abs --clearsign > deb/dists/stable/InRelease

echo "Generating public key..."
gpg --local-user BBECB4C2D2872160 --armor --export --output deb/gpg

echo -e "Done!\nAll files are in deb/dists/stable/\n"
