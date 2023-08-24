#!/bin/sh

echo "Package is being purged"
if systemctl is-enabled --quiet border0.service; then systemctl disable border0.service; fi
if systemctl is-active --quiet border0.service; then systemctl stop border0.service; fi
if [ -f /etc/systemd/system/border0.service ]; then rm /etc/systemd/system/border0.service; fi

systemctl daemon-reload

if [ -f /usr/bin/border0 ]; then rm /usr/bin/border0; fi
if [ -d /etc/border0 ]; then rm -rf /etc/border0; fi
