#!/bin/bash

# Exit on any error
set -e

# Check if the input format is correct
if [[ $1 =~ ^v([0-9.]+)-([0-9]+)-g([a-f0-9]+)$ ]]; then
    VERSION=${BASH_REMATCH[1]}
    RELEASE=${BASH_REMATCH[2]}.g${BASH_REMATCH[3]}
else
    echo "Invalid format"
    exit 1
fi

# Variables
YOUR_EMAIL_ADDRESS="support@border0.com"
YOUR_NAME="border0"
FILE_ARCH=$2
# we mar ARCH values between debian and redhat
if [[ "$FILE_ARCH" == "amd64" ]]; then
    ARCH="x86_64"
fi
if [[ "$FILE_ARCH" == "arm64" ]]; then
    ARCH="aarch64"
fi

RPM_PATH="$HOME/rpmbuild/RPMS/$ARCH/border0-$VERSION-$RELEASE.el9.$ARCH.rpm"
REPO_DIR="$HOME/rpm"


# Input validations
if [[ -z "$ARCH" || -z "$VERSION" ]]; then
    echo "Usage: $0 <architecture> <version>"
    exit 1
fi

# # Install required tools
# sudo dnf install -y rpm-build rpm-sign rpmdevtools createrepo


# RPM Build
rpmdev-setuptree
echo "setting up directories..."

cp ./bin/mysocketctl_linux_${FILE_ARCH} $HOME/rpmbuild/SOURCES/border0

# Write the SPEC file
cat <<EOL > $HOME/rpmbuild/SPECS/border0.spec
Name:       border0
Version:    $VERSION
Release:    $RELEASE%{?dist}

Summary:    Border0 Connector and CLI tooling

License:    Proprietary
URL:        https://border0.com
Source0:    border0

%description
Border0 Connector and CLI tooling

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
cp %{SOURCE0} %{buildroot}/usr/bin/border0
chmod +x %{buildroot}/usr/bin/border0

%post
if [ $1 -eq 1 ]; then
    # This is a fresh install
    echo "Fresh install script goes here"
elif [ $1 -eq 2 ]; then
    # This is an upgrade
    echo "Upgrading script gpes here"
fi


%files
/usr/bin/border0

%changelog
* Date $YOUR_NAME - $VERSION
- RPM package for version $VERSION
EOL

# Build the RPM package
rpmbuild -ba $HOME/rpmbuild/SPECS/border0.spec 

# Configure RPM for Signing
echo "Configuring RPM for signing..."
echo "%_signature gpg" > ~/.rpmmacros
echo "%_gpg_name $YOUR_EMAIL_ADDRESS" >> ~/.rpmmacros

# Sign the RPM
echo "Signing the RPM..."
echo rpm --addsign $RPM_PATH
rpm --addsign $RPM_PATH

mkdir -p $REPO_DIR/$ARCH
cp $RPM_PATH $REPO_DIR/$ARCH/

echo "Done, your $RPM_PATH is signed"


