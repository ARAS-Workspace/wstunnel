# Distribution

## Branches

```
main     upstream base + our patches + bump.sh          no CI, no FFI
linux    main + release-linux.yaml                      linux-v*  →  wstunnel_<version>_linux_<arch>.tar.gz
apple    main + wstunnel-apple + release-{mac,ios}      mac-v*    →  libwstunnel_apple.a (arm64 + x86_64)
                                                        ios-v*    →  WstunnelKit.xcframework
```

## Set up the worktrees

```bash
W=/path/to/wstunnel                       # directory that holds .bare + the checkouts

git clone --bare git@github.com:ARAS-Workspace/wstunnel.git "$W/.bare"
git --git-dir="$W/.bare" remote add upstream https://github.com/erebe/wstunnel.git
git --git-dir="$W/.bare" fetch upstream --tags

for b in main linux apple; do
  git --git-dir="$W/.bare" worktree add "$W/$b" "$b"
done
```

## Take an upstream commit

```bash
git -C "$W/main" cherry-pick -x <upstream-sha>
git -C "$W/main" push origin main

git -C "$W/linux" merge main
git -C "$W/apple" merge main
```

## Release

```bash
W=/path/to/wstunnel
V=10.5.2+Phantom.Patch.2

for b in main linux apple; do (cd "$W/$b" && .github/scripts/bump.sh "$V"); done

git -C "$W/main"  push origin main
git -C "$W/linux" push origin linux
git -C "$W/apple" push origin apple

(cd "$W/linux" && .github/scripts/release-linux.sh)
(cd "$W/apple" && .github/scripts/release-mac.sh)
(cd "$W/apple" && .github/scripts/release-ios.sh)
```

## Verify

```bash
for b in main linux apple; do
  printf "%-7s %s\n" "$b" "$(grep -m1 '^version' "$W/$b/wstunnel/Cargo.toml")"
done

gh run list --repo ARAS-Workspace/wstunnel --limit 5
gh release list --repo ARAS-Workspace/wstunnel
```

## Consume

```bash
# frontmatter — vendored tarballs, version pinned in binary_utils.py
gh release download "linux-v$V" --repo ARAS-Workspace/wstunnel \
  --pattern 'wstunnel_*_linux_*.tar.gz' \
  --dir phantom_frontmatter/bin/lib/

# app-mac
gh release download "mac-v$V" --repo ARAS-Workspace/wstunnel --dir /tmp/wsa
tar -xzf /tmp/wsa/*.tar.gz -C Libraries/WstunnelKit/

# app-ios
gh release download "ios-v$V" --repo ARAS-Workspace/wstunnel --dir /tmp/wsa
unzip -o /tmp/wsa/*.zip -d Libraries/WstunnelKit/
```
