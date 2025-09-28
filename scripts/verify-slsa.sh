#!/bin/bash

# SLSA Provenance Verification Script for Caddy
# This script verifies the SLSA provenance and in-toto attestations for Caddy releases

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to download and verify Caddy release
verify_caddy_release() {
    local version=$1
    local platform=$2
    local arch=$3
    
    print_status $BLUE "Verifying Caddy release: $version for $platform/$arch"
    
    # Download the release artifact
    local artifact_name="caddy_${version}_${platform}_${arch}"
    if [[ "$platform" == "darwin" ]]; then
        artifact_name="caddy_${version}_mac_${arch}"
    fi
    
    print_status $YELLOW "Downloading artifact: $artifact_name"
    
    # Download the binary
    local binary_url="https://github.com/caddyserver/caddy/releases/download/v${version}/${artifact_name}"
    curl -L -o "${artifact_name}" "$binary_url" || {
        print_status $RED "Failed to download binary from $binary_url"
        return 1
    }
    
    # Download the SLSA provenance bundle
    local provenance_url="https://github.com/caddyserver/caddy/releases/download/v${version}/${artifact_name}.intoto.bundle"
    curl -L -o "${artifact_name}.intoto.bundle" "$provenance_url" || {
        print_status $RED "Failed to download SLSA provenance from $provenance_url"
        return 1
    }
    
    # Download the SBOM bundle
    local sbom_url="https://github.com/caddyserver/caddy/releases/download/v${version}/${artifact_name}.sbom.bundle"
    curl -L -o "${artifact_name}.sbom.bundle" "$sbom_url" || {
        print_status $RED "Failed to download SBOM from $sbom_url"
        return 1
    }
    
    # Verify SLSA provenance
    print_status $YELLOW "Verifying SLSA provenance..."
    if cosign verify-blob-attestation \
        --bundle "${artifact_name}.intoto.bundle" \
        --type slsaprovenance \
        "${artifact_name}"; then
        print_status $GREEN "✅ SLSA provenance verification successful"
    else
        print_status $RED "❌ SLSA provenance verification failed"
        return 1
    fi
    
    # Verify SBOM
    print_status $YELLOW "Verifying SBOM..."
    if cosign verify-blob-attestation \
        --bundle "${artifact_name}.sbom.bundle" \
        --type https://cyclonedx.org/bom \
        "${artifact_name}"; then
        print_status $GREEN "✅ SBOM verification successful"
    else
        print_status $RED "❌ SBOM verification failed"
        return 1
    fi
    
    # Extract and display provenance information
    print_status $YELLOW "Extracting provenance information..."
    cosign verify-blob-attestation \
        --bundle "${artifact_name}.intoto.bundle" \
        --type slsaprovenance \
        --output json \
        "${artifact_name}" | jq -r '.payload' | base64 -d | jq '.predicate' > provenance.json
    
    print_status $BLUE "Build Information:"
    echo "  Version: $(jq -r '.buildType' provenance.json)"
    echo "  Builder: $(jq -r '.builder.id' provenance.json)"
    echo "  Build ID: $(jq -r '.metadata.buildInvocationId' provenance.json)"
    echo "  Build Time: $(jq -r '.metadata.buildStartedOn' provenance.json)"
    echo "  Repository: $(jq -r '.invocation.configSource.uri' provenance.json)"
    echo "  Commit: $(jq -r '.invocation.configSource.digest.sha1' provenance.json)"
    
    # Clean up
    rm -f "${artifact_name}" "${artifact_name}.intoto.bundle" "${artifact_name}.sbom.bundle" provenance.json
    
    print_status $GREEN "🎉 All verifications completed successfully!"
}

# Main function
main() {
    print_status $BLUE "Caddy SLSA Provenance Verification Tool"
    print_status $BLUE "======================================"
    
    # Check dependencies
    if ! command_exists cosign; then
        print_status $RED "❌ cosign is not installed. Please install it first:"
        echo "  go install github.com/sigstore/cosign/cmd/cosign@latest"
        exit 1
    fi
    
    if ! command_exists jq; then
        print_status $RED "❌ jq is not installed. Please install it first:"
        echo "  # On Ubuntu/Debian: sudo apt-get install jq"
        echo "  # On macOS: brew install jq"
        echo "  # On Windows: choco install jq"
        exit 1
    fi
    
    if ! command_exists curl; then
        print_status $RED "❌ curl is not installed. Please install it first."
        exit 1
    fi
    
    # Parse command line arguments
    if [ $# -lt 1 ]; then
        print_status $YELLOW "Usage: $0 <version> [platform] [arch]"
        echo "  version: Caddy version (e.g., 2.7.6)"
        echo "  platform: linux, darwin, windows (default: linux)"
        echo "  arch: amd64, arm64, arm (default: amd64)"
        echo ""
        echo "Examples:"
        echo "  $0 2.7.6"
        echo "  $0 2.7.6 darwin arm64"
        echo "  $0 2.7.6 windows amd64"
        exit 1
    fi
    
    local version=$1
    local platform=${2:-linux}
    local arch=${3:-amd64}
    
    # Validate platform
    case $platform in
        linux|darwin|windows)
            ;;
        *)
            print_status $RED "❌ Invalid platform: $platform. Must be one of: linux, darwin, windows"
            exit 1
            ;;
    esac
    
    # Validate architecture
    case $arch in
        amd64|arm64|arm)
            ;;
        *)
            print_status $RED "❌ Invalid architecture: $arch. Must be one of: amd64, arm64, arm"
            exit 1
            ;;
    esac
    
    # Verify the release
    verify_caddy_release "$version" "$platform" "$arch"
}

# Run main function with all arguments
main "$@"
