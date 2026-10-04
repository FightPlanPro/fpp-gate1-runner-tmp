#!/bin/bash
# One Replit session: create a local key, publish only the public key, wait for a matching seal, then run Gate 1.
set -u
umask 077
KEYDIR="$HOME/.fpp-gate1"
WORKDIR="/tmp/fpp-gate1"
mkdir -p "$KEYDIR" "$WORKDIR"
chmod 700 "$KEYDIR" "$WORKDIR"

cleanup_gh() {
  gh auth logout --hostname github.com >/dev/null 2>&1 || true
  rm -rf "$HOME/.config/gh"
}

if ! test -s "$KEYDIR/priv.pem"; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEYDIR/priv.pem" >/dev/null 2>&1
fi
chmod 600 "$KEYDIR/priv.pem"
openssl pkey -in "$KEYDIR/priv.pem" -pubout -outform PEM -out "$KEYDIR/pub.pem"
openssl pkey -in "$KEYDIR/priv.pem" -pubout -outform DER -out "$KEYDIR/pub.der"
chmod 600 "$KEYDIR/pub.pem" "$KEYDIR/pub.der"
if grep -q "PRIVATE KEY" "$KEYDIR/pub.pem"; then
  echo "PUBLIC_FILE_REJECTED=YES"
  exit 1
fi
PUB_SHA=$(openssl dgst -sha256 "$KEYDIR/pub.der" | awk '{print $2}')
echo "PUBLIC_KEY_SHA256=$PUB_SHA"
echo "GITHUB_DEVICE_LOGIN_START=YES"
trap cleanup_gh EXIT
gh auth login --hostname github.com --git-protocol https --web --skip-ssh-key -s gist || {
  echo "GITHUB_LOGIN_FAILED=YES"
  exit 1
}
GIST_URL=$(gh gist create "$KEYDIR/pub.pem" --public --desc fpp-gate1-public-key) || {
  echo "GIST_CREATE_FAILED=YES"
  exit 1
}
echo "GIST_URL=$GIST_URL"
echo "SEND_GIST_URL_NOW=YES"
cleanup_gh
trap - EXIT
echo "GITHUB_AUTH_REMOVED=YES"
echo "WAITING_FOR_SEAL=YES"

FOUND=""
SEAL_SHA=""
SEAL_URL=""
i=0
while test "$i" -lt 80; do
  i=$((i + 1))
  body=$(curl -fsSL -H "Accept: application/vnd.github.raw" -H "Cache-Control: no-cache" \
    "https://api.github.com/repos/FightPlanPro/fpp-gate1-runner-tmp/contents/current-seal.manifest?ref=main" || true)
  pub=$(printf '%s\n' "$body" | awk -F= '$1=="PUB_SHA256"{print $2}' | tr -d '\r')
  seal=$(printf '%s\n' "$body" | awk -F= '$1=="SEALED_SHA256"{print $2}' | tr -d '\r')
  url=$(printf '%s\n' "$body" | awk -F= '$1=="SEALED_URL"{sub(/^[^=]*=/,""); print}' | tr -d '\r')
  if test "$pub" = "$PUB_SHA" && printf '%s' "$seal" | grep -Eq '^[0-9a-f]{64}$' && printf '%s' "$url" | grep -Eq '^https://raw.githubusercontent.com/FightPlanPro/fpp-gate1-runner-tmp/[0-9a-f]{40}/sealed.bin$'; then
    FOUND=YES
    SEAL_SHA=$seal
    SEAL_URL=$url
    break
  fi
  echo "SEAL_POLL=$i"
  sleep 15
done
if test "$FOUND" != "YES"; then
  echo "SEAL_WAIT_TIMEOUT=YES"
  echo "PRIVATE_KEY_REMAINS_ON_REPLIT=YES"
  exit 1
fi

curl -fsSL -o "$WORKDIR/sealed.bin" "$SEAL_URL"
test "$(openssl dgst -sha256 "$WORKDIR/sealed.bin" | awk '{print $2}')" = "$SEAL_SHA" || {
  echo "SEALED_HASH_MISMATCH=YES"
  exit 1
}
test "$(openssl dgst -sha256 "$KEYDIR/pub.der" | awk '{print $2}')" = "$PUB_SHA" || {
  echo "PUB_HASH_MISMATCH=YES"
  exit 1
}
curl -fsSL -o "$WORKDIR/preflight.mjs" "https://raw.githubusercontent.com/FightPlanPro/fpp-gate1-runner-tmp/99138905644e613dc890cb767e756ef6f031aa8b/gate1-r2-preflight.mjs"
curl -fsSL -o "$WORKDIR/gate1.mjs" "https://raw.githubusercontent.com/FightPlanPro/fpp-gate1-runner-tmp/2896bcf5ad374c26a752926bdc057af72b50a6d2/gate1-pre-cutover-object-sync.mjs"
test "$(openssl dgst -sha256 "$WORKDIR/preflight.mjs" | awk '{print $2}')" = "d98c4f13c0fce6cf78fb7d7c7c8beb0196da63f152129546941db407ef85e016" || {
  echo "PREFLIGHT_HASH_MISMATCH=YES"
  exit 1
}
test "$(openssl dgst -sha256 "$WORKDIR/gate1.mjs" | awk '{print $2}')" = "f1a8638c235c2ff0b851dea2a85ea52b62494c464e87dfd1f457954d61b91562" || {
  echo "HELPER_HASH_MISMATCH=YES"
  exit 1
}
cp "$KEYDIR/priv.pem" "$WORKDIR/priv.pem"
cp "$KEYDIR/pub.der" "$WORKDIR/pub.der"
chmod 600 "$WORKDIR/priv.pem" "$WORKDIR/pub.der" "$WORKDIR/sealed.bin"
npm install --silent --prefix "$WORKDIR" @google-cloud/storage@7.19.0 @aws-sdk/client-s3@3.1136.0
node "$WORKDIR/preflight.mjs"
status=$?
if test "$status" = 0; then
  rm -f "$KEYDIR/priv.pem" "$KEYDIR/pub.pem" "$KEYDIR/pub.der" "$WORKDIR/priv.pem" "$WORKDIR/sealed.bin"
  echo "LOCAL_PRIVATE_KEY_REMOVED=YES"
fi
exit "$status"
