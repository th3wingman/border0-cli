#!/bin/bash

function create_config_file {
  echo "Creating config file..."
  echo """
token: ${BORDER0_CONNECTOR_TOKEN}
""" >/etc/border0/border0.yaml
}

function check_and_replace {
  if [ -f /usr/local/bin/border0 ]; then
    echo "Replacing /usr/local/bin/border0 with symlink to /usr/bin/border0"
    rm /usr/local/bin/border0
    ln -s /usr/bin/border0 /usr/local/bin/border0
  fi
}

case "$1" in
1)
  # This corresponds to initial installation
  check_and_replace
  if [ -n "$BORDER0_CONNECTOR_TOKEN" ]; then
    border0 connector install --v2 --daemon-only
    create_config_file
  else
    if [ -f /etc/systemd/system/border0.service ]; then
      echo "Looks like border0.service is already installed."
      exit 0
    fi
    echo "Running Border0 Connector Install."
    attempts=3
    while [ $attempts -gt 0 ]; do
      read -p "Do you want to proceed? (y/n) " choice
      case "$choice" in
      y | Y)
        echo "Running 'border0 connector install --v2'"
        border0 connector install --v2
        break
        ;;
      n | N)
        echo "You can always execute 'border0 connector install --v2' to install the connector later."
        break
        ;;
      *)
        echo -e "Invalid choice. \nYou can always execute 'border0 connector install --v2' to install the connector later."
        let "attempts--"
        if [ $attempts -eq 0 ]; then
          echo "Exceeded maximum number of attempts."
          break
        fi
        continue
        ;;
      esac
    done
  fi
  ;;
2)
  # This corresponds to upgrade
  echo "Upgrading Border0 Connector..."
  if systemctl is-active --quiet border0.service; then
    echo "Restarting border0.service..."
    systemctl restart border0.service
  fi
  ;;
0)
echo "Package is being purged"
if systemctl is-enabled --quiet border0.service; then systemctl disable border0.service; fi
if systemctl is-active --quiet border0.service; then systemctl stop border0.service; fi
if [ -f /etc/systemd/system/border0.service ]; then rm /etc/systemd/system/border0.service; fi

systemctl daemon-reload

if [ -f /usr/local/bin/border0 ]; then rm /usr/local/bin/border0; fi
if [ -f /usr/bin/border0 ]; then rm /usr/bin/border0; fi
if [ -d /etc/border0 ]; then rm -rf /etc/border0; fi

;;
*)
  echo "Unknown argument: $1"
  ;;
esac
