#!/bin/bash
# Builds, signs and installs Safeguard.app to /Applications, then removes the local
# copy so Spotlight only ever shows one Safeguard. Usage: ./build.sh [--install]
set -euo pipefail
cd "$(dirname "$0")"

APP=build/Safeguard.app
ENGINE=../safeguard.py

# Universal binary so the same DMG runs on Apple silicon and Intel Macs.
ARCHS=()
if [ "${SAFEGUARD_UNIVERSAL:-1}" = "1" ]; then ARCHS=(--arch arm64 --arch x86_64); fi

echo "› Compiling (release)…"
swift build -c release "${ARCHS[@]}"

if [ ! -f build/AppIcon.icns ] || [ Scripts/make_icon.swift -nt build/AppIcon.icns ]; then
  echo "› Drawing app icon…"
  rm -rf build/AppIcon.iconset
  mkdir -p build/AppIcon.iconset
  swift Scripts/make_icon.swift build/icon-1024.png >/dev/null
  swift Scripts/make_icon.swift build/icon-small.png compact >/dev/null
  # 16-64 px slots use the simplified mark so the radar survives; 128 px and up use the full one.
  for s in 16 32; do
    sips -z $s $s build/icon-small.png --out build/AppIcon.iconset/icon_${s}x${s}.png >/dev/null
    sips -z $((s * 2)) $((s * 2)) build/icon-small.png --out build/AppIcon.iconset/icon_${s}x${s}@2x.png >/dev/null
  done
  for s in 128 256 512; do
    sips -z $s $s build/icon-1024.png --out build/AppIcon.iconset/icon_${s}x${s}.png >/dev/null
    sips -z $((s * 2)) $((s * 2)) build/icon-1024.png --out build/AppIcon.iconset/icon_${s}x${s}@2x.png >/dev/null
  done
  iconutil -c icns build/AppIcon.iconset -o build/AppIcon.icns
fi

echo "› Assembling ${APP}…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$(swift build -c release "${ARCHS[@]}" --show-bin-path)/Safeguard" "$APP/Contents/MacOS/Safeguard"
cp "$ENGINE" "$APP/Contents/Resources/safeguard.py"
cp build/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cp Resources/Fonts/*.ttf Resources/Fonts/OFL-*.txt "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Safeguard</string>
  <key>CFBundleDisplayName</key><string>Safeguard</string>
  <key>CFBundleIdentifier</key><string>local.safeguard.app</string>
  <key>CFBundleExecutable</key><string>Safeguard</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.1</string>
  <key>CFBundleVersion</key><string>2</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Personal security monitor. Runs entirely on this Mac.</string>
</dict>
</plist>
PLIST

# Sign with a stable identity when one exists, so macOS keeps Keychain and
# Full Disk Access grants across rebuilds. Falls back to ad-hoc on a bare Mac.
IDENTITY="${SAFEGUARD_SIGN_IDENTITY:-$(security find-identity -p codesigning -v 2>/dev/null \
  | sed -n 's/.*"\(Apple Development:.*\)"/\1/p' | head -1)}"
if [ -n "$IDENTITY" ]; then
  codesign --force --deep --sign "$IDENTITY" "$APP" >/dev/null
  echo "› Signed as $IDENTITY"
else
  codesign --force --deep --sign - "$APP" >/dev/null
fi

# Install the signed bundle and keep no second copy in the repo: a build in
# ~/dev would otherwise show up in Spotlight beside the installed app.
rm -rf /Applications/Safeguard.app
cp -R "$APP" /Applications/
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f /Applications/Safeguard.app >/dev/null 2>&1 || true
rm -rf "$APP"
echo "✓ Installed to /Applications/Safeguard.app (local build copy removed)"
