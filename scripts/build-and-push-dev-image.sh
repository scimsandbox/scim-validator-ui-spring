#!/usr/bin/env bash

set -euo pipefail

no_cache=false
push_image=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-cache)
      no_cache=true
      ;;
    --push)
      push_image=true
      ;;
    -h|--help)
      echo "Usage: $0 [--push] [--no-cache]"
      echo "  Default: builds locally for current host architecture without pushing to Docker"
      echo "  --push: builds multi-architecture images and pushes to Docker registry"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--push] [--no-cache]" >&2
      exit 1
      ;;
  esac

  shift
done

cd "$(dirname "$0")/.."

maven_settings="${MAVEN_SETTINGS:-$HOME/.m2/settings.xml}"
maven_security="${MAVEN_SECURITY:-$HOME/.m2/settings-security.xml}"
temp_security_file=""

cleanup() {
  if [[ -n "$temp_security_file" && -f "$temp_security_file" ]]; then
    rm -f "$temp_security_file"
  fi
}

trap cleanup EXIT

if [[ ! -f "$maven_settings" ]]; then
  printf 'Missing Maven settings file: %s\n' "$maven_settings" >&2
  exit 1
fi

if [[ ! -f "$maven_security" ]]; then
  temp_security_file="$(mktemp)"
  maven_security="$temp_security_file"
fi

if [[ "$push_image" == true ]]; then
  docker_args=(docker buildx build --platform linux/amd64,linux/arm64 --push)
else
  docker_args=(docker buildx build --load)
fi

if [[ "$no_cache" == true ]]; then
  docker_args+=(--no-cache)
fi
docker_args+=(
  --secret "id=maven_settings,src=$maven_settings"
  --secret "id=maven_security,src=$maven_security"

  -t edipal/scim-validator-ui-spring:dev
  .
)

"${docker_args[@]}"