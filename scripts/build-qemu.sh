#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=qemu/source.lock
source "$root_dir/qemu/source.lock"
source_dir=${QEMU_SOURCE_DIR:-$root_dir/third_party/qemu}
build_dir=${QEMU_BUILD_DIR:-$root_dir/build/qemu}
jobs=${QEMU_JOBS:-$(getconf _NPROCESSORS_ONLN)}

patch_fingerprint() (
    cd -- "$root_dir"
    {
        sha256sum qemu/patches/series
        while IFS= read -r patch || [[ -n $patch ]]; do
            [[ -z $patch || $patch == \#* ]] && continue
            sha256sum "qemu/patches/$patch"
        done < qemu/patches/series
    } | sha256sum | cut -d' ' -f1
)

cloned=0
if [[ ! -e $source_dir ]]; then
    mkdir -p -- "$(dirname -- "$source_dir")"
    git clone --no-checkout --filter=blob:none "$QEMU_REPOSITORY" "$source_dir"
    cloned=1
fi
if [[ ! -d $source_dir/.git ]]; then
    printf 'QEMU source directory is not a Git checkout: %s\n' "$source_dir" >&2
    exit 1
fi

actual_origin=$(git -C "$source_dir" remote get-url origin)
if [[ $actual_origin != "$QEMU_REPOSITORY" ]]; then
    printf 'Unexpected QEMU origin: %s\n' "$actual_origin" >&2
    exit 1
fi
if ! git -C "$source_dir" cat-file -e "$QEMU_COMMIT^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$QEMU_COMMIT"
fi
if ((cloned)); then
    git -C "$source_dir" checkout --detach "$QEMU_COMMIT"
fi
if [[ $(git -C "$source_dir" rev-parse HEAD) != "$QEMU_COMMIT" ]]; then
    printf 'QEMU source HEAD does not match %s\n' "$QEMU_COMMIT" >&2
    exit 1
fi
patch_marker=$source_dir/.git/vulnFuzz-applied-patches
current_patch_fingerprint=$(patch_fingerprint)
patches_applied=0
if ! git -C "$source_dir" diff --ignore-submodules=all --quiet \
    || ! git -C "$source_dir" diff --cached --ignore-submodules=all --quiet; then
    if [[ ! -f $patch_marker ]] || [[ $(<"$patch_marker") != "$current_patch_fingerprint" ]]; then
        printf 'QEMU source has local changes; refusing to overwrite them\n' >&2
        exit 1
    fi
    patches_applied=1
else
    rm -f -- "$patch_marker"
fi
for submodule in roms/seabios roms/ipxe; do
    if [[ -e $source_dir/$submodule/.git ]] \
        && { ! git -C "$source_dir/$submodule" diff --quiet \
            || ! git -C "$source_dir/$submodule" diff --cached --quiet; }; then
        printf 'QEMU submodule has local changes: %s\n' "$submodule" >&2
        exit 1
    fi
done

git -C "$source_dir" submodule update --init --depth 1 roms/seabios roms/ipxe
if ((!patches_applied)); then
    while IFS= read -r patch || [[ -n $patch ]]; do
        [[ -z $patch || $patch == \#* ]] && continue
        git -C "$source_dir" apply --check "$root_dir/qemu/patches/$patch"
    done < "$root_dir/qemu/patches/series"
    while IFS= read -r patch || [[ -n $patch ]]; do
        [[ -z $patch || $patch == \#* ]] && continue
        git -C "$source_dir" apply "$root_dir/qemu/patches/$patch"
    done < "$root_dir/qemu/patches/series"
    printf '%s\n' "$current_patch_fingerprint" > "$patch_marker"
fi

mkdir -p -- "$build_dir"
cd -- "$build_dir"
export LC_ALL=C
export TZ=UTC
export PYTHONHASHSEED=0
export SOURCE_DATE_EPOCH=$(git -C "$source_dir" show -s --format=%ct "$QEMU_COMMIT")

"$source_dir/configure" \
    --target-list=x86_64-softmmu,x86_64-linux-user \
    --with-pkgversion="vulnFuzz-${QEMU_COMMIT:0:12}" \
    --without-default-features \
    --enable-tcg \
    --enable-plugins \
    --enable-tools \
    --disable-docs \
    --disable-werror
make -j"$jobs"

{
    printf 'repository=%s\n' "$QEMU_REPOSITORY"
    printf 'tag=%s\n' "$QEMU_TAG"
    printf 'commit=%s\n' "$QEMU_COMMIT"
    printf 'submodules:\n'
    git -C "$source_dir" submodule status roms/seabios roms/ipxe
    printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
    printf 'cc='; cc --version | sed -n '1p'
    printf 'make='; make --version | sed -n '1p'
    printf 'ninja='; ninja --version
    printf 'python='; python3 --version
    printf 'qemu='; ./qemu-system-x86_64 --version | sed -n '1p'
    printf 'qemu_sha256='; sha256sum ./qemu-system-x86_64 | cut -d' ' -f1
    printf 'qemu_img='; ./qemu-img --version | sed -n '1p'
    printf 'qemu_img_sha256='; sha256sum ./qemu-img | cut -d' ' -f1
    printf 'patches_sha256:\n'
    while IFS= read -r patch || [[ -n $patch ]]; do
        [[ -z $patch || $patch == \#* ]] && continue
        sha256sum "$root_dir/qemu/patches/$patch"
    done < "$root_dir/qemu/patches/series"
} > provenance.txt

printf 'QEMU built at %s/qemu-system-x86_64\n' "$build_dir"
