#!/usr/bin/env bash
# Bump the fork version across every workspace member that carries one.
# The member list is read from the root Cargo.toml, so this script is
# identical on every branch regardless of which crates that branch has.
#
# The scheme is <upstream-version>+Phantom.Patch.<n>: the upstream base
# stays, the counter records how many patch rounds we applied.
# Rewrites the manifests and commits them as `Bump version <new>`,
# leaving only the push to the operator.
# Usage:
#   .github/scripts/bump.sh                  10.5.2 → 10.5.2+Phantom.Patch.1
#                                            …Patch.1 → …Patch.2
#   .github/scripts/bump.sh 10.6.2           set explicitly (new upstream base)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ROOT_MANIFEST="${REPO_ROOT}/Cargo.toml"

# The commit below stages explicit paths, but a dirty tree still means
# the operator has work in flight that a version commit would sit on
# top of unreviewed.
if ! git -C "${REPO_ROOT}" diff --quiet || ! git -C "${REPO_ROOT}" diff --cached --quiet; then
    echo "ERROR: working tree has uncommitted changes — commit or stash them first" >&2
    git -C "${REPO_ROOT}" status --short >&2
    exit 1
fi

read_version() {
    awk -F\" '/^version *= */ {print $2; exit}' "$1"
}

# Workspace members, from the root manifest. Handles the array whether
# it sits on one line or spans several.
mapfile -t MEMBERS < <(awk '
    /^members *= *\[/ { inside = 1 }
    inside           { buf = buf $0 }
    inside && /\]/   { inside = 0 }
    END {
        n = split(buf, parts, "\"")
        for (i = 2; i <= n; i += 2) print parts[i]
    }
' "$ROOT_MANIFEST")

if [[ "${#MEMBERS[@]}" -eq 0 ]]; then
    echo "ERROR: no workspace members parsed from ${ROOT_MANIFEST}" >&2
    exit 1
fi

# Keep only members that carry a literal version line; one that
# inherits (version.workspace = true) has nothing for us to rewrite.
MANIFESTS=()
SKIPPED=()
for m in "${MEMBERS[@]}"; do
    path="${REPO_ROOT}/${m}/Cargo.toml"
    if [[ ! -f "$path" ]]; then
        echo "ERROR: member '${m}' has no Cargo.toml at ${path}" >&2
        exit 1
    fi
    if [[ -n "$(read_version "$path")" ]]; then
        MANIFESTS+=("$path")
    else
        SKIPPED+=("$m")
    fi
done

if [[ "${#MANIFESTS[@]}" -eq 0 ]]; then
    echo "ERROR: no member carries a literal version line" >&2
    exit 1
fi

CURRENT="$(read_version "${MANIFESTS[0]}")"

# Every manifest must agree before we touch anything.
for m in "${MANIFESTS[@]}"; do
    got="$(read_version "$m")"
    if [[ "$got" != "$CURRENT" ]]; then
        echo "ERROR: ${m#"${REPO_ROOT}/"} is at '${got}', expected '${CURRENT}'" >&2
        exit 1
    fi
done

if [[ $# -ge 1 ]]; then
    NEW="$1"
elif [[ "$CURRENT" =~ ^(.+)\+Phantom\.Patch\.([0-9]+)$ ]]; then
    NEW="${BASH_REMATCH[1]}+Phantom.Patch.$(( BASH_REMATCH[2] + 1 ))"
else
    NEW="${CURRENT}+Phantom.Patch.1"
fi

if [[ "$NEW" == "$CURRENT" ]]; then
    echo "ERROR: new version equals current version (${CURRENT})" >&2
    exit 1
fi

CHANGED=0
for m in "${MANIFESTS[@]}"; do
    awk -v new="$NEW" '
        BEGIN { done = 0 }
        /^version *= */ && !done { sub(/".*"/, "\"" new "\""); done = 1 }
        { print }
    ' "$m" > "${m}.tmp"
    mv "${m}.tmp" "$m"
    if [[ "$(read_version "$m")" == "$NEW" ]]; then
        CHANGED=$(( CHANGED + 1 ))
    fi
done

# A partial rewrite ships a binary that lies about its own version,
# so this is an error, not a warning.
if [[ "$CHANGED" -ne "${#MANIFESTS[@]}" ]]; then
    echo "ERROR: rewrote ${CHANGED}/${#MANIFESTS[@]} manifests — tree is inconsistent" >&2
    exit 1
fi

git -C "${REPO_ROOT}" commit --quiet --only -m "Bump version ${NEW}" -- "${MANIFESTS[@]}"

echo "${CURRENT} → ${NEW}  (${CHANGED} of ${#MEMBERS[@]} members)"
for m in "${MANIFESTS[@]}"; do
    echo "  ${m#"${REPO_ROOT}/"}"
done
echo
git -C "${REPO_ROOT}" log -1 --format="committed %h %s"
if [[ "${#SKIPPED[@]}" -gt 0 ]]; then
    for s in "${SKIPPED[@]}"; do
        echo "  skipped (no literal version): ${s}"
    done
fi
