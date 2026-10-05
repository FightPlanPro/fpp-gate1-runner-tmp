#!/bin/bash
set -eu
umask 077
cd "$HOME/workspace"
test -s fpp-gate1-pub.der
if grep -q "PRIVATE KEY" fpp-gate1-pub.der; then
  echo PRIVATE_KEY_BLOCKED=YES
  exit 1
fi
openssl pkey -pubin -inform DER -in fpp-gate1-pub.der -noout
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
printf '%s\n' 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' > "$d/kh"
printf '%s\n' "$DEPLOY_KEY_B64" | base64 -d > "$d/k"
chmod 600 "$d/k"
export GIT_SSH_COMMAND="ssh -i $d/k -o IdentitiesOnly=yes -o UserKnownHostsFile=$d/kh -o StrictHostKeyChecking=yes"
git init -q "$d/r"
git -C "$d/r" checkout -q -b incoming-pub
cp fpp-gate1-pub.der "$d/r/fpp-gate1-pub.der"
git -C "$d/r" -c user.email=fightplanproapp@gmail.com -c user.name=FightPlanPro add fpp-gate1-pub.der
git -C "$d/r" -c user.email=fightplanproapp@gmail.com -c user.name=FightPlanPro commit -qm "Publish Gate 1 public key only"
git -C "$d/r" push -q -f git@github.com:FightPlanPro/fpp-gate1-runner-tmp.git incoming-pub
echo PUBLIC_KEY_PUBLISHED=YES
