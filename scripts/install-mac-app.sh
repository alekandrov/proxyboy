#!/bin/bash
# Crea Proxyboy.app (macOS) que corre el código de este repo: después de un `git pull` alcanza con reabrirla.
# Uso: npm run install-app            → /Applications (o ~/Applications si no se puede escribir)
#      npm run install-app -- <dir>   → en otra carpeta
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ELECTRON_APP="$REPO/node_modules/electron/dist/Electron.app"
DEST_DIR="${1:-/Applications}"
[ -w "$DEST_DIR" ] || DEST_DIR="$HOME/Applications"
mkdir -p "$DEST_DIR"
APP="$DEST_DIR/Proxyboy.app"
# Ruta del repo como string de JS (bash 3.2 de macOS no tiene ${var@Q})
REPO_JS="\"$(printf '%s' "$REPO" | sed 's/\\/\\\\/g; s/"/\\"/g')\""

if [ "$(uname)" != "Darwin" ]; then echo "Este script es solo para macOS" >&2; exit 1; fi
if [ ! -d "$ELECTRON_APP" ]; then echo "Falta Electron: corré 'npm install' en $REPO" >&2; exit 1; fi

# Si está abierta, la cerramos (Proxyboy restaura el proxy del sistema al salir)
if pgrep -f "$APP/Contents/MacOS/" >/dev/null 2>&1; then
  echo "Cerrando Proxyboy…"
  osascript -e 'tell application "Proxyboy" to quit' >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do pgrep -f "$APP/Contents/MacOS/" >/dev/null 2>&1 || break; sleep 0.5; done
fi

echo "Creando $APP…"
rm -rf "$APP"
# Copia del runtime de Electron con nuestro nombre e ícono
ditto "$ELECTRON_APP" "$APP"
mv "$APP/Contents/MacOS/Electron" "$APP/Contents/MacOS/Proxyboy"
cp "$REPO/build/icon.icns" "$APP/Contents/Resources/proxyboy.icns"
PLIST="$APP/Contents/Info.plist"
plutil -replace CFBundleName -string "Proxyboy" "$PLIST"
plutil -replace CFBundleDisplayName -string "Proxyboy" "$PLIST"
plutil -replace CFBundleExecutable -string "Proxyboy" "$PLIST"
plutil -replace CFBundleIdentifier -string "com.proxyboy.app" "$PLIST"
plutil -replace CFBundleIconFile -string "proxyboy.icns" "$PLIST"
plutil -remove CFBundleIconName "$PLIST" 2>/dev/null || true

# "App" mínima que carga el código del repo (Electron carga Resources/app automáticamente)
mkdir -p "$APP/Contents/Resources/app"
cat > "$APP/Contents/Resources/app/package.json" <<EOF
{ "name": "proxyboy", "productName": "Proxyboy", "main": "index.js" }
EOF
cat > "$APP/Contents/Resources/app/index.js" <<EOF
// Generado por scripts/install-mac-app.sh: corre Proxyboy desde el repo
const fs = require('fs');
const { app, dialog } = require('electron');
const REPO = ${REPO_JS};
const main = REPO + '/src/main/main.js';
if (!fs.existsSync(main)) {
  app.whenReady().then(() => {
    dialog.showErrorBox('Proxyboy', 'No se encontró el repo en ' + REPO + '. Volvé a correr "npm run install-app" desde el repo.');
    app.quit();
  });
} else {
  // Las apps abiertas desde el Finder no heredan el PATH de la terminal (Homebrew, Android SDK…)
  process.env.PATH = ['/opt/homebrew/bin', '/usr/local/bin', process.env.PATH].join(':');
  process.chdir(REPO);
  require(main);
}
EOF

# Al cambiar Info.plist y Resources hay que volver a firmar (firma local, ad-hoc)
codesign --force --deep --sign - "$APP" >/dev/null 2>&1
# Que el Finder y el Dock tomen el ícono nuevo
touch "$APP"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP" >/dev/null 2>&1 || true

echo "Listo: $APP"
echo "Abrila desde Aplicaciones, Launchpad o Spotlight (⌘ Espacio → Proxyboy)."
