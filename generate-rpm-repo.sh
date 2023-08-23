# Setup Local RPM Repository
#!/bin/bash
REPO_DIR="$HOME/rpm"
REPO_FILE_PATH="$REPO_DIR/border0.repo"

gpg --armor --export support@border0.com > $REPO_DIR/RPM-GPG-KEY
echo "GPG key exported to $REPO_DIR/RPM-GPG-KEY"

createrepo $REPO_DIR
echo "Repo created in $REPO_DIR"

# Generate .repo file
echo "Generating .repo file..."
cat <<EOL | tee $REPO_FILE_PATH
[rpm]
name=Border0 Public RPM Repository
baseurl=http://download.border0.com/rpm/
enabled=1
gpgcheck=1
gpgkey=http://download.border0.com/rpm/RPM-GPG-KEY
EOL

echo "All done! Your repo is now hosted and ready for distribution."
