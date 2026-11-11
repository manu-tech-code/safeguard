#!/bin/bash
# Builds a shareable Safeguard.dmg from the signed app in /Applications.
# Usage: ./release.sh        -> dist/Safeguard-1.0.dmg
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/Safeguard.app/Contents/Info.plist)
OUT=../dist
STAGE=/tmp/safeguard-release
DMG="$OUT/Safeguard-$VERSION.dmg"

if [ ! -d /Applications/Safeguard.app ]; then
  echo "› No installed app; building first…"
  ./build.sh
fi

echo "› Staging…"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$OUT"
ditto /Applications/Safeguard.app "$STAGE/Safeguard.app"
ln -s /Applications "$STAGE/Applications"
cp Resources/INSTALL.txt "$STAGE/INSTALL.txt"

echo "› Packing ${DMG}…"
rm -f "$DMG"
hdiutil create -volname Safeguard -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null

IDENTITY=$(security find-identity -p codesigning -v 2>/dev/null \
  | sed -n 's/.*"\(Apple Development:.*\)"/\1/p' | head -1)
if [ -n "$IDENTITY" ]; then
  codesign --force --sign "$IDENTITY" "$DMG" >/dev/null
  echo "› Signed image as $IDENTITY"
fi

hdiutil verify "$DMG" >/dev/null
rm -rf "$STAGE"
echo "✓ ${DMG} ($(du -h "$DMG" | cut -f1))"
