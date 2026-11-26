#!/bin/bash
# Compila la app Proxyboy VPN sin Gradle (solo SDK build-tools + JDK 11+) y deja el APK en src/main/assets/.
set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
BT="$SDK/build-tools/$(ls "$SDK/build-tools" | grep -v rc | sort -V | tail -1)"
PLATFORM="$SDK/platforms/$(ls "$SDK/platforms" | sort -V | tail -1)"
ANDROID_JAR="$PLATFORM/android.jar"
OUT=build
APK=../src/main/assets/proxyboy-vpn.apk
KEYSTORE=proxyboy-vpn.keystore

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/res"

# Keystore fijo (no es secreto: solo permite actualizar la app instalada sin desinstalarla)
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -keystore "$KEYSTORE" -storepass proxyboy -keypass proxyboy -alias proxyboy \
    -keyalg RSA -keysize 2048 -validity 36500 -dname "CN=Proxyboy VPN" >/dev/null
fi

"$BT/aapt2" compile --dir res -o "$OUT/res.zip"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$ANDROID_JAR" --manifest AndroidManifest.xml \
  --min-sdk-version 24 --target-sdk-version 35 "$OUT/res.zip"

javac -source 11 -target 11 -nowarn -Xlint:-options -encoding UTF-8 -classpath "$ANDROID_JAR" \
  -d "$OUT/classes" $(find src -name '*.java')
"$BT/d8" --min-api 24 --lib "$ANDROID_JAR" --output "$OUT" $(find "$OUT/classes" -name '*.class')

cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT" && zip -q unsigned.apk classes.dex)
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
mkdir -p "$(dirname "$APK")"
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:proxyboy --key-pass pass:proxyboy --out "$APK" "$OUT/aligned.apk"
rm -f "$APK.idsig"
echo "APK: $(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")"
