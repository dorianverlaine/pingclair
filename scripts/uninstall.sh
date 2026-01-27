#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}🗑️ Pingclair Uninstaller${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo bash uninstall.sh)${NC}"
  exit 1
fi

# 1. Stop and Disable Service
echo "Stopping and removing systemd service..."
systemctl stop pingclair || true
systemctl disable pingclair || true
rm -f /etc/systemd/system/pingclair.service
systemctl daemon-reload

# 2. Remove Binary and Symlink
echo "Removing binary and symlink..."
rm -f /usr/local/bin/pingclair
rm -f /usr/local/bin/pc

# 3. Ask about Config and Data
read -p "Do you want to remove configuration and logs? (/etc/Pingclair, /var/log/pingclair) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing /etc/Pingclair..."
    rm -rf /etc/Pingclair
    echo "Removing /var/log/pingclair..."
    rm -rf /var/log/pingclair
    echo "Removing /var/lib/pingclair..."
    rm -rf /var/lib/pingclair
fi

# 4. Remove User
read -p "Do you want to remove the 'pingclair' system user? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing user 'pingclair'..."
    userdel pingclair || true
fi

echo -e "${GREEN}✅ Uninstallation Complete!${NC}"
