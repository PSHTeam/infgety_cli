#!/bin/bash

# =============================================================================
# INFGETY CLI - DATABASE MANAGEMENT TOOL
# =============================================================================
# Command-line interface for managing Infgety databases including encryption
# and archiving for distribution in the Infgety app ecosystem.
# 
# Usage:
#   ./infgety-cli.sh <command> [OPTIONS] <target>
#   ./infgety-cli.sh encrypt --file myfile.dart
#   ./infgety-cli.sh encrypt --dir ./lib
#   ./infgety-cli.sh archive --database ./path/to/database
# =============================================================================

# =============================================================================
# CONFIGURATION
# =============================================================================
INFGETY_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArOQnu+Ba41wRQSs8dZ3B
1A1Uh0fV+ckTnGe+5PRpzR47pDLgH6CYctSaLwI/qQPo6S3Sgdiu/ypgrKZqP5uU
VOgTZF7/hPDVbM4iZy5pDKmLTdeBPCOLAQgEKXwkuYkGRg0ii35lxT4n7ytiEw6c
AYyYThzI9o6Tof5zKhCmcLgoq3W/znorXFOYneFkQxMPNJrz7OiO60L0AGwD/EjP
+iKqr+0OBBF8KYUv1NgboH6BptlBDTiLh+1AejTbTSrKe0iUf6FK0Ljjm0MeRZQi
HP1CMUGUZBNkqMlwARR7Aq0LST+apKxwhh+jgGuRKM+xcBKDYBIwMzOYvdJ2HhKn
hoMoKVOTaAElR4i+Ytl6bxz8nJ4umsHk5mZEofQ0V6TnJUSIokXFhwGqwrI2TOSW
1eKC4VhPSxLekjvmCD7EG02H1SR32GSwa9Z/+ASN61i3ik6hamzI2sEKTKzR9ao5
o0DQUHtd0sZWZCoiZZ8/To6m+njmwbh8SX+KQtsSjS3iR3ZbAspEyehaykrRX+o7
MnvLbNQ50F/WH0pJ+GfS2PqVMk5qfNpQp4kWz1/mVURyvuKSrmpY5iatmdBQbF+q
6ByKQriyQg96eqAsFl/cFrioBj78jWsGn26Hcdx47cFT7aLdQU1h221igzRnQUPo
I+jgge7sT4Sq4Q57ULmDZWUCAwEAAQ==
-----END PUBLIC KEY-----"

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# FUNCTIONS
# =============================================================================

# Function to display usage
show_usage() {
    echo "Infgety CLI - Database Management Tool"
    echo ""
    echo "Usage: $(basename "$0") <command> [OPTIONS]"
    echo ""
    echo "COMMANDS:"
    echo "  encrypt    Encrypt Dart files using AES-256-CBC"
    echo "  archive    Create database archive for distribution"
    echo "  create     Scaffold a new template-based project (e.g. database)"
    echo "  help       Show this help message"
    echo ""
    echo "ENCRYPT COMMAND:"
    echo "  $(basename "$0") encrypt --file <file>              Encrypt single Dart file"
    echo "  $(basename "$0") encrypt --dir <directory>          Encrypt all Dart files in directory"
    echo ""
    echo "  Options:"
    echo "    --file <path>         Target Dart file to encrypt"
    echo "    --dir <path>          Target directory to encrypt"
    echo "    --key <key>           Encryption key (32 UTF-8 or 64 hex chars) [REQUIRED]"
    echo "    --iv <iv>             Initialization vector (32 hex chars) [REQUIRED]"
    echo "    --key-format <fmt>    Key format: 'hex' or 'utf8' (default: hex)"
    echo "    --recursive           Process subdirectories (default: true)"
    echo "    --no-recursive        Don't process subdirectories"
    echo "    --verbose             Show detailed output"
    echo "    -h, --help            Show command-specific help"
    echo ""
    echo "ARCHIVE COMMAND:"
    echo "  $(basename "$0") archive --database <path>          Create database archive"
    echo ""
    echo "  Options:"
    echo "    --database <path>     Database directory to archive"
    echo "    --id <identifier>     Database identifier (e.g., com.example)"
    echo "    --output <dir>        Output directory (default: current)"
    echo "    --encrypt             Encrypt Dart files with random keys before archiving"
    echo "    --sign                Generate signatures for files (use with --encrypt)"
    echo "    --verbose             Show detailed output"
    echo "    -h, --help            Show command-specific help"
    echo ""
    echo "CREATE COMMAND:"
    echo "  $(basename "$0") create --template <template> --output <dir>"
    echo ""
    echo "  Options:"
    echo "    --template <name>     Template name to scaffold (e.g., database)"
    echo "    --output <dir>        Output directory for the new project"
    echo "    --id <identifier>     Database identifier (e.g., com.example)"
    echo "    --verbose             Show detailed output"
    echo "    -h, --help            Show command-specific help"
    echo ""
}

log_info() {
    if [[ "$QUIET" != true ]]; then
        echo -e "${BLUE}$1${NC}"
    fi
}

log_success() {
    if [[ "$QUIET" != true ]]; then
        echo -e "${GREEN}$1${NC}"
    fi
}

log_warning() {
    echo -e "${YELLOW}$1${NC}" >&2
}

log_error() {
    echo -e "${RED}$1${NC}" >&2
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${CYAN}$1${NC}"
    fi
}

is_valid_utf8_key() {
    local key="$1"
    if [[ ${#key} -ne 32 ]]; then
        return 1
    fi
    return 0
}

is_valid_hex_key() {
    local key="$1"
    if [[ ${#key} -ne 64 ]]; then
        return 1
    fi
    if [[ ! "$key" =~ ^[0-9a-fA-F]+$ ]]; then
        return 1
    fi
    return 0
}

is_valid_hex_iv() {
    local iv="$1"
    if [[ ${#iv} -ne 32 ]]; then
        return 1
    fi
    if [[ ! "$iv" =~ ^[0-9a-fA-F]+$ ]]; then
        return 1
    fi
    return 0
}

# Function to convert hex key to binary for OpenSSL
hex_to_openssl_key() {
    local hex_key="$1"
    echo "$hex_key"
}

# Function to generate random hex string
generate_random_hex() {
    local length="$1"
    openssl rand -hex $((length / 2))
}

# Function to generate or load database encryption keys
generate_or_load_keys() {
    local database_dir="$1"
    local keys_file="$database_dir/infgety_keys.json"
    
    if [[ -f "$keys_file" ]]; then
        log_verbose "Loading existing encryption keys from: $keys_file"
        
        # Validate JSON file
        if ! jq empty "$keys_file" 2>/dev/null; then
            log_error "Error: Invalid JSON in keys file: $keys_file"
            return 1
        fi
        
        # Extract key and IV
        local key=$(jq -r '.key' "$keys_file" 2>/dev/null)
        local iv=$(jq -r '.iv' "$keys_file" 2>/dev/null)
        
        if [[ -z "$key" || "$key" == "null" || -z "$iv" || "$iv" == "null" ]]; then
            log_error "Error: Invalid key or IV in keys file: $keys_file"
            return 1
        fi
        
        # Validate key and IV format
        if ! is_valid_hex_key "$key" || ! is_valid_hex_iv "$iv"; then
            log_error "Error: Invalid key or IV format in keys file: $keys_file"
            return 1
        fi
        
        # Set global variables instead of echoing
        ARCHIVE_KEY="$key"
        ARCHIVE_IV="$iv"
        return 0
    else
        log_verbose "Generating new random encryption keys..."
        
        # Generate random key (64 hex chars = 32 bytes = 256 bits)
        local new_key=$(generate_random_hex 64)
        # Generate random IV (32 hex chars = 16 bytes = 128 bits)
        local new_iv=$(generate_random_hex 32)
        
        log_verbose "Generated key: $new_key"
        log_verbose "Generated IV: $new_iv"
        
        # Create JSON with keys
        local keys_json=$(jq -n \
            --arg key "$new_key" \
            --arg iv "$new_iv" \
            '{key: $key, iv: $iv, generated_by: "infgety-cli", timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")}')
        
        # Save keys to file
        echo "$keys_json" > "$keys_file"
        log_success "✓ Generated and saved new encryption keys to: $keys_file"
        
        # Set global variables instead of echoing
        ARCHIVE_KEY="$new_key"
        ARCHIVE_IV="$new_iv"
        return 0
    fi
}

# Function to encrypt keys with RSA public key
encrypt_keys_with_rsa() {
    local keys_file="$1"
    local encrypted_keys_file="$2"
    
    log_verbose "Encrypting keys file with RSA public key..."
    
    # Create temporary file for public key
    local temp_pubkey=$(mktemp)
    echo "$INFGETY_PUBLIC_KEY" > "$temp_pubkey"
    
    # Encrypt the keys file using RSA public key with OAEP padding
    if openssl pkeyutl -encrypt -pubin -inkey "$temp_pubkey" -pkeyopt rsa_padding_mode:oaep -in "$keys_file" -out "$encrypted_keys_file" 2>/dev/null; then
        log_verbose "✓ Keys encrypted successfully with RSA"
        rm -f "$temp_pubkey"
        return 0
    else
        log_error "Error: Failed to encrypt keys with RSA public key"
        log_error "This might be due to key size limitations. Trying alternative method..."
        rm -f "$temp_pubkey"
        
        # Try alternative method with smaller payload
        local temp_small_keys=$(mktemp)
        jq -c '{key: .key, iv: .iv}' "$keys_file" > "$temp_small_keys"
        
        # Try again with smaller file
        echo "$INFGETY_PUBLIC_KEY" > "$temp_pubkey"
        if openssl pkeyutl -encrypt -pubin -inkey "$temp_pubkey" -pkeyopt rsa_padding_mode:oaep -in "$temp_small_keys" -out "$encrypted_keys_file" 2>/dev/null; then
            log_verbose "✓ Keys encrypted successfully with RSA (compact format)"
            rm -f "$temp_pubkey" "$temp_small_keys"
            return 0
        else
            log_error "Error: RSA encryption failed even with compact format"
            rm -f "$temp_pubkey" "$temp_small_keys"
            return 1
        fi
    fi
}

# Function to generate signatures for files
generate_file_signatures() {
    local database_dir="$1"
    local sign_files="$2"
    
    if [[ "$sign_files" != true ]]; then
        return 0
    fi
    
    log_info "Generating file signatures..."
    
    local signatures_file="$database_dir/infgety_signatures.json"
    local signatures_json='{"signatures": {}, "generated_by": "infgety-cli", "algorithm": "SHA-256"}'
    
    # Change to database directory for relative paths
    local original_dir=$(pwd)
    cd "$database_dir"
    
    # Generate signatures for encrypted Dart files in bin/
    if [[ -d "bin" ]]; then
        local bin_dart_files=$(find bin -type f -name '*.dart.enc' 2>/dev/null || true)
        if [[ -n "$bin_dart_files" ]]; then
            while IFS= read -r file; do
                if [[ -n "$file" && -f "$file" ]]; then
                    local signature=$(shasum -a 256 "$file" | cut -d' ' -f1)
                    signatures_json=$(echo "$signatures_json" | jq --arg file "$file" --arg sig "$signature" '.signatures[$file] = $sig')
                    log_verbose "Generated signature for: $file"
                fi
            done <<< "$bin_dart_files"
        fi
    fi
    
    # Generate signatures for encrypted Dart files in lib/
    if [[ -d "lib" ]]; then
        local lib_dart_files=$(find lib -type f -name '*.dart.enc' 2>/dev/null || true)
        if [[ -n "$lib_dart_files" ]]; then
            while IFS= read -r file; do
                if [[ -n "$file" && -f "$file" ]]; then
                    local signature=$(shasum -a 256 "$file" | cut -d' ' -f1)
                    signatures_json=$(echo "$signatures_json" | jq --arg file "$file" --arg sig "$signature" '.signatures[$file] = $sig')
                    log_verbose "Generated signature for: $file"
                fi
            done <<< "$lib_dart_files"
        fi
    fi
    
    # Generate signatures for .arb files in l10n/
    if [[ -d "l10n" ]]; then
        local arb_files=$(find l10n -type f -name '*.arb' 2>/dev/null || true)
        if [[ -n "$arb_files" ]]; then
            while IFS= read -r file; do
                if [[ -n "$file" && -f "$file" ]]; then
                    local signature=$(shasum -a 256 "$file" | cut -d' ' -f1)
                    signatures_json=$(echo "$signatures_json" | jq --arg file "$file" --arg sig "$signature" '.signatures[$file] = $sig')
                    log_verbose "Generated signature for: $file"
                fi
            done <<< "$arb_files"
        fi
    fi
    
    # Generate signature for pubspec.yaml
    if [[ -f "pubspec.yaml" ]]; then
        local signature=$(shasum -a 256 "pubspec.yaml" | cut -d' ' -f1)
        signatures_json=$(echo "$signatures_json" | jq --arg file "pubspec.yaml" --arg sig "$signature" '.signatures[$file] = $sig')
        log_verbose "Generated signature for: pubspec.yaml"
    fi
    
    # Generate signature for README.md if it exists
    if [[ -f "README.md" ]]; then
        local signature=$(shasum -a 256 "README.md" | cut -d' ' -f1)
        signatures_json=$(echo "$signatures_json" | jq --arg file "README.md" --arg sig "$signature" '.signatures[$file] = $sig')
        log_verbose "Generated signature for: README.md"
    fi
    
    # Add timestamp
    signatures_json=$(echo "$signatures_json" | jq '.timestamp = (now | todate)')
    
    # Save signatures to file
    echo "$signatures_json" | jq '.' > "$signatures_file"
    
    cd "$original_dir"
    
    log_success "✓ File signatures generated successfully"
    return 0
}

# Function to validate database structure
validate_database_structure() {
    local database_dir="$1"
    
    log_verbose "Validating database structure in '$database_dir'..."
    
    # Check if directory exists
    if [[ ! -d "$database_dir" ]]; then
        log_error "Error: Database directory '$database_dir' does not exist"
        return 1
    fi
    
    # Check required files/directories
    local required_items=("bin" "lib" "pubspec.yaml" "l10n")
    local missing_items=()
    
    for item in "${required_items[@]}"; do
        if [[ ! -e "$database_dir/$item" ]]; then
            missing_items+=("$item")
        fi
    done
    
    if [[ ${#missing_items[@]} -gt 0 ]]; then
        log_error "Error: Missing required database components:"
        for item in "${missing_items[@]}"; do
            log_error "  - $item"
        done
        return 1
    fi
    
    # Check that bin is a directory
    if [[ ! -d "$database_dir/bin" ]]; then
        log_error "Error: 'bin' must be a directory"
        return 1
    fi

    # Check if install.dart and fetch_contacts.dart exist in bin
    if [[ ! -f "$database_dir/bin/install.dart" ]]; then
        log_error "Error: 'bin/install.dart' must exist"
        return 1
    fi

    if [[ ! -f "$database_dir/bin/fetch_contacts.dart" ]]; then
        log_error "Error: 'bin/fetch_contacts.dart' must exist"
        return 1
    fi
    
    # Check that lib is a directory
    if [[ ! -d "$database_dir/lib" ]]; then
        log_error "Error: 'lib' must be a directory"
        return 1
    fi
    
    # Check that l10n is a directory
    if [[ ! -d "$database_dir/l10n" ]]; then
        log_error "Error: 'l10n' must be a directory"
        return 1
    fi
    
    # Check that l10n contains at least one .arb file
    local arb_files=$(find "$database_dir/l10n" -type f -name '*.arb' 2>/dev/null || true)
    if [[ -z "$arb_files" ]]; then
        log_error "Error: 'l10n' directory must contain at least one .arb file"
        return 1
    fi
    
    # Check that pubspec.yaml is a file
    if [[ ! -f "$database_dir/pubspec.yaml" ]]; then
        log_error "Error: 'pubspec.yaml' must be a file"
        return 1
    fi
    
    log_verbose "✓ Database structure validation passed"
    return 0
}

# Function to get database identifier from pubspec.yaml
get_database_identifier() {
    local database_dir="$1"
    local pubspec_file="$database_dir/pubspec.yaml"
    
    if [[ ! -f "$pubspec_file" ]]; then
        log_error "Error: pubspec.yaml not found"
        return 1
    fi
    
    # Extract identifier from pubspec.yaml
    # Look for infgety.identifier or fallback to name
    local identifier=""
    
    # Try to get infgety identifier first
    if grep -q "^infgety:" "$pubspec_file"; then
        identifier=$(grep -A 10 "^infgety:" "$pubspec_file" | grep "identifier:" | head -1 | sed 's/.*identifier:[[:space:]]*//' | sed 's/[[:space:]]*$//' | sed 's/^["\x27]*//' | sed 's/["\x27]*$//')
    fi
    
    # Fallback to name if no infgety identifier
    if [[ -z "$identifier" ]]; then
        identifier=$(grep "^name:" "$pubspec_file" | head -1 | sed 's/name:[[:space:]]*//' | sed 's/[[:space:]]*$//' | sed 's/^["\x27]*//' | sed 's/["\x27]*$//')
    fi
    
    if [[ -z "$identifier" ]]; then
        log_error "Error: Could not extract database identifier from pubspec.yaml"
        return 1
    fi
    
    echo "$identifier"
    return 0
}

# Function to create database archive
create_database_archive() {
    local database_dir="$1"
    local database_id="$2"
    local output_dir="$3"
    local encrypt_before="$4"
    local sign_files="$5"
    
    log_info "Creating database archive for '$database_id'..."
    
    # Validate database structure
    if ! validate_database_structure "$database_dir"; then
        return 1
    fi
    
    # Create output directory if it doesn't exist
    if [[ ! -d "$output_dir" ]]; then
        log_verbose "Creating output directory: $output_dir"
        mkdir -p "$output_dir"
    fi
    
    # Generate or load encryption keys if encryption is requested
    local archive_key="$KEY"
    local archive_iv="$IV"
    local keys_file=""
    local encrypted_keys_file=""
    
    if [[ "$encrypt_before" == true ]]; then
        log_info "Setting up encryption keys for archive..."
        
        # Generate or load database-specific keys (sets ARCHIVE_KEY and ARCHIVE_IV)
        if ! generate_or_load_keys "$database_dir"; then
            log_error "Error: Failed to generate or load encryption keys"
            return 1
        fi
        
        # Use the generated/loaded keys
        archive_key="$ARCHIVE_KEY"
        archive_iv="$ARCHIVE_IV"
        
        keys_file="$database_dir/infgety_keys.json"
        encrypted_keys_file="infgety_keys.json.enc"
        
        log_verbose "Using archive key: $archive_key"
        log_verbose "Using archive IV: $archive_iv"
    fi
    
    # Change to the database directory for easier archiving
    local original_dir=$(pwd)
    cd "$database_dir"
    
    # Collect files to archive
    local archive_items=()
    local cleanup_files=()
    
    # Always include required items
    archive_items+=("bin" "lib" "pubspec.yaml" "l10n")
    
    # Add optional items if they exist
    [[ -f "README.md" ]] && archive_items+=("README.md")
    
    # Encrypt Dart files if requested
    if [[ "$encrypt_before" == true ]]; then
        log_info "Encrypting Dart files before archiving..."
        
        # Encrypt files in bin directory
        if [[ -d "bin" ]]; then
            local bin_dart_files=$(find bin -type f -name '*.dart' 2>/dev/null || true)
            if [[ -n "$bin_dart_files" ]]; then
                while IFS= read -r file; do
                    if [[ -n "$file" ]]; then
                        log_verbose "Encrypting: $file"
                        if encrypt_file "$file" "${file}.enc" "$archive_key" "$archive_iv" true; then
                            cleanup_files+=("${file}.enc")
                        else
                            log_error "Failed to encrypt: $file"
                            cd "$original_dir"
                            return 1
                        fi
                    fi
                done <<< "$bin_dart_files"
            fi
        fi
        
        # Encrypt files in lib directory
        if [[ -d "lib" ]]; then
            local lib_dart_files=$(find lib -type f -name '*.dart' 2>/dev/null || true)
            if [[ -n "$lib_dart_files" ]]; then
                while IFS= read -r file; do
                    if [[ -n "$file" ]]; then
                        log_verbose "Encrypting: $file"
                        if encrypt_file "$file" "${file}.enc" "$archive_key" "$archive_iv" true; then
                            cleanup_files+=("${file}.enc")
                        else
                            log_error "Failed to encrypt: $file"
                            cd "$original_dir"
                            return 1
                        fi
                    fi
                done <<< "$lib_dart_files"
            fi
        fi
        
        # Encrypt the keys file for inclusion in archive
        if [[ -f "infgety_keys.json" ]]; then
            log_verbose "Encrypting keys file for archive inclusion..."
            if encrypt_keys_with_rsa "infgety_keys.json" "$encrypted_keys_file"; then
                archive_items+=("$encrypted_keys_file")
                cleanup_files+=("$encrypted_keys_file")
                log_verbose "✓ Keys file encrypted and added to archive"
            else
                log_error "Error: Failed to encrypt keys file"
                cd "$original_dir"
                return 1
            fi
        fi
        
        # Generate file signatures if requested
        if [[ "$sign_files" == true ]]; then
            if ! generate_file_signatures "$original_dir/$database_dir" "$sign_files"; then
                log_error "Error: Failed to generate file signatures"
                cd "$original_dir"
                return 1
            fi
            
            # Encrypt the signatures file to prevent tampering
            if [[ -f "infgety_signatures.json" ]]; then
                log_verbose "Encrypting signatures file for security..."
                if encrypt_file "infgety_signatures.json" "infgety_signatures.json.enc" "$archive_key" "$archive_iv" true true; then
                    archive_items+=("infgety_signatures.json.enc")
                    cleanup_files+=("infgety_signatures.json.enc")
                    cleanup_files+=("infgety_signatures.json")  # Also cleanup the unencrypted version
                    log_verbose "✓ Signatures file encrypted and added to archive"
                else
                    log_error "Error: Failed to encrypt signatures file"
                    cd "$original_dir"
                    return 1
                fi
            fi
        fi
        
        # When encrypting, remove original dart files from archive and replace with encrypted ones
        log_verbose "Preparing archive with encrypted files only..."
        
        # Create custom archive structure when encrypting
        local temp_archive_dir=$(mktemp -d)
        log_verbose "Created temporary directory: $temp_archive_dir"
        
        # Copy non-dart files and directories
        for item in "${archive_items[@]}"; do
            if [[ "$item" == "bin" || "$item" == "lib" ]]; then
                # For bin and lib, copy directory structure but handle dart files specially
                mkdir -p "$temp_archive_dir/$item"
                
                # Copy non-dart files
                find "$item" -type f ! -name '*.dart' -exec cp {} "$temp_archive_dir/{}" \; 2>/dev/null || true
                
                # Copy encrypted dart files
                find "$item" -type f -name '*.dart.enc' -exec cp {} "$temp_archive_dir/{}" \; 2>/dev/null || true
                
                # Copy directory structure
                find "$item" -type d -exec mkdir -p "$temp_archive_dir/{}" \; 2>/dev/null || true
            else
                # Copy other items as-is
                if [[ -f "$item" ]]; then
                    cp "$item" "$temp_archive_dir/"
                elif [[ -d "$item" ]]; then
                    cp -r "$item" "$temp_archive_dir/"
                fi
            fi
        done
        
        # Update archive items to use temp directory
        cd "$temp_archive_dir"
        archive_items=()
        for item in bin lib pubspec.yaml l10n; do
            [[ -e "$item" ]] && archive_items+=("$item")
        done
        [[ -f "README.md" ]] && archive_items+=("README.md")
        [[ -f "$encrypted_keys_file" ]] && archive_items+=("$encrypted_keys_file")
        [[ -f "infgety_signatures.json.enc" ]] && archive_items+=("infgety_signatures.json.enc")
        
        log_success "✓ Dart files encrypted successfully"
    fi
    
    # Create the archive
    local archive_name="${database_id}.zip"
    local archive_path="$original_dir/$output_dir/$archive_name"

    # Check if archive file already exists
    if [[ -f "$archive_path" ]]; then
        log_warning "Warning: Existing archive '$output_dir/$archive_name' will be replaced."
        rm -f "$archive_path"
    fi
    
    log_info "Creating archive: $archive_name"
    log_verbose "Archive items: ${archive_items[*]}"
    
    # Check if zip command is available
    if ! command -v zip &> /dev/null; then
        log_error "Error: 'zip' command is not available"
        log_error "Please install zip to create archives"
        cd "$original_dir"
        return 1
    fi
    
    # Create the zip file
    if zip -r "$archive_path" "${archive_items[@]}"; then
        log_success "✓ Archive created successfully"
        
        # Show archive info
        if [[ -f "$archive_path" ]]; then
            local archive_size=$(du -h "$archive_path" | cut -f1)
            log_info "Archive size: $archive_size"
            
            if [[ "$VERBOSE" == true ]]; then
                log_verbose "Archive contents:"
                if zip -l "$archive_path" | tail -n +4 | head -n -2 > /dev/null 2>&1; then
                    zip -l "$archive_path" | tail -n +4 | head -n -2 | sed 's/^/  /'
                else
                    # Fallback method
                    zip -l "$archive_path" | grep -E "^\s*[0-9]+" | sed 's/^/  /'
                fi
            fi
        else
            log_error "Warning: Archive file not found at $archive_path"
        fi
    else
        log_error "Error: Failed to create archive"
        cd "$original_dir"
        return 1
    fi
    
    # Cleanup encrypted files when encryption is used
    if [[ "$encrypt_before" == true ]]; then
        log_info "Cleaning up encrypted files..."
        
        # Go back to original database directory for cleanup
        cd "$original_dir"
        cd "$database_dir"
        
        for file in "${cleanup_files[@]}"; do
            if [[ -f "$file" ]]; then
                log_verbose "Removing: $file"
                rm -f "$file"
            fi
        done
        log_success "✓ Cleanup completed"
        
        # Return to original directory before cleaning temp directory
        cd "$original_dir"
    fi
    
    # Clean up temporary directory if it was created
    if [[ "$encrypt_before" == true && -n "$temp_archive_dir" && -d "$temp_archive_dir" ]]; then
        log_verbose "Cleaning up temporary directory: $temp_archive_dir"
        rm -rf "$temp_archive_dir"
    fi
    
    cd "$original_dir"
    return 0
}

# Function to encrypt a single file
encrypt_file() {
    local input_file="$1"
    local output_file="$2"
    local key="$3"
    local iv="$4"
    local key_is_hex="$5"
    local suppress_warning="$6"  # Optional parameter to suppress non-Dart file warning
    
    # Check if input file exists
    if [[ ! -f "$input_file" ]]; then
        log_error "Error: Input file '$input_file' does not exist"
        return 1
    fi
    
    # Check if input file is a Dart file
    if [[ ! "$input_file" =~ \.dart$ && "$suppress_warning" != true ]]; then
        log_warning "Warning: Input file '$input_file' doesn't have .dart extension"
    fi
    
    # Check if output file already exists
    if [[ -f "$output_file" ]]; then
        log_warning "Warning: Output file '$output_file' already exists, overwriting..."
    fi
    
    log_verbose "Encrypting '$input_file' to '$output_file'..."
    
    # Prepare OpenSSL command based on key format
    local openssl_key
    if [[ "$key_is_hex" == true ]]; then
        openssl_key="$key"
    else
        # Convert UTF-8 key to hex for OpenSSL
        openssl_key=$(echo -n "$key" | xxd -p | tr -d '\n')
    fi
    
    # Encrypt the file using OpenSSL
    # Note: We need to use the exact same format as Dart's encrypt package
    # The encrypt package uses PKCS7 padding by default
    if openssl enc -aes-256-cbc -in "$input_file" -K "$openssl_key" -iv "$iv" -base64 -A > "$output_file"; then
        log_verbose "✓ Successfully encrypted '$input_file' to '$output_file'"
        local original_size=$(wc -c < "$input_file")
        local encrypted_size=$(wc -c < "$output_file")
        log_verbose "File size: $original_size bytes → $encrypted_size bytes (base64 encoded)"
        return 0
    else
        log_error "Error: Failed to encrypt '$input_file'"
        return 1
    fi
}

# Function to find and encrypt Dart files in a directory
encrypt_directory() {
    local directory="$1"
    local key="$2"
    local iv="$3"
    local key_is_hex="$4"
    local recursive="$5"
    
    if [[ ! -d "$directory" ]]; then
        log_error "Error: Directory '$directory' does not exist"
        return 1
    fi
    
    # Find Dart files
    local dart_files
    if [[ "$recursive" != true ]]; then
        dart_files=$(find "$directory" -maxdepth 1 -type f -name '*.dart' 2>/dev/null | grep -v '\.dart\.enc$' || true)
    else
        dart_files=$(find "$directory" -type f -name '*.dart' 2>/dev/null | grep -v '\.dart\.enc$' || true)
    fi
    
    if [[ -z "$dart_files" ]]; then
        log_warning "No Dart files found in '$directory'"
        return 0
    fi
    
    # Count files
    local file_count
    file_count=$(echo "$dart_files" | wc -l)
    log_info "Found $file_count Dart file(s) to encrypt in '$directory'"
    
    # Process each file
    local success_count=0
    local failed_count=0
    
    while IFS= read -r file; do
        if [[ -z "$file" ]]; then
            continue
        fi
        
        local output_file="${file}.enc"
        
        log_verbose "Processing: $file"
        
        if encrypt_file "$file" "$output_file" "$key" "$iv" "$key_is_hex"; then
            ((success_count++))
            log_success "✓ $file"
        else
            ((failed_count++))
            log_error "✗ $file"
        fi
    done <<< "$dart_files"
    
    # Summary
    log_success "Encryption completed in '$directory'!"
    log_success "Successfully encrypted: $success_count file(s)"
    if [[ $failed_count -gt 0 ]]; then
        log_error "Failed to encrypt: $failed_count file(s)"
        return 1
    fi
    
    
    return 0
}

# Function to create a new project from a built‑in template
create_template() {
    local template="$1"
    local target_dir="$2"
    local identifier="$3"

    case "$template" in
        database)
            create_database_template "$template" "$target_dir" "$identifier"
            ;;
        *)
        log_error "Unknown template: $template"
        exit 1
        ;;
    esac
}

create_database_template() {
    local template="$1"
    local target_dir="$2"
    local identifier="$3"

    log_info "🛠  Dart console template → $target_dir"


    if [[ "$VERBOSE" == true ]]; then
        log_verbose "Creating database template in '$target_dir' with identifier '$identifier'"
        log_verbose "Running 'dart create --no-pub -t console' in '$target_dir'"
        # Show output of dart create command
        dart create --no-pub -t console "$target_dir" || {
            log_error "Failed to run 'dart create'. Do you have the Dart SDK installed?"
            exit 1
        }
    else
        dart create --no-pub -t console "$target_dir" >/dev/null 2>&1 || {
            log_error "Failed to run 'dart create'. Do you have the Dart SDK installed?"
            exit 1
        }     
    fi

    # Wipe out the generated bin/ and lib/ contents:
    rm -rf "$target_dir/bin/"* "$target_dir/lib/"*
    mkdir -p "$target_dir/bin" "$target_dir/lib" "$target_dir/l10n"

    # 1) bin/install.dart
    cat > "$target_dir/bin/install.dart" <<'EOF'
import 'package:database/on_install.dart';

Future<void> main() async {
  await onInstall();
}
EOF

    # 2) bin/fetch_contacts.dart
    cat > "$target_dir/bin/fetch_contacts.dart" <<'EOF'
import 'package:database/on_fetch_contacts.dart';
import 'package:infgety_database/infgety_database.dart';

Future<List<ContactName>> main(List<String> args) async {
  final query = FetchContactsQuery.fromArgs(args);

  final contacts = await onFetchContacts(
    regionCode: query.regionCode,
    countryCode: query.countryCode,
    nationalNumber: query.nationalNumber,
  );

  return contacts;
}
EOF

    # 3) bin/db.json
    cat > "$target_dir/bin/db.json" <<'EOF'
{
  "US": {
    "1234567890": [
      { "name": "John Doe", "quantity": 1 },
      { "name": "John", "quantity": 4 },
      { "name": "Dr. John", "quantity": 2 }
    ],
    "0987654321": [
      { "name": "Jane Smith", "quantity": 3 },
      { "name": "Jane", "quantity": 5 }
    ]
  },
  "YE": {
    "777123456": [
      { "name": "أحمد محمد", "quantity": 2 },
      { "name": "أحمد", "quantity": 5 },
      { "name": "أبو محمد", "quantity": 1 }
    ],
    "777654321": [
      { "name": "سالم علي", "quantity": 3 },
      { "name": "سالم", "quantity": 2 }
    ]
  },
  "SA": {
    "501234567": [
      { "name": "عبدالله سعود", "quantity": 4 },
      { "name": "عبدالله", "quantity": 6 },
      { "name": "أبو سعود", "quantity": 2 }
    ],
    "509876543": [
      { "name": "سارة محمد", "quantity": 3 },
      { "name": "سارة", "quantity": 5 }
    ]
  },
  "IN": {
    "9123456789": [
      { "name": "Rahul Sharma", "quantity": 3 },
      { "name": "Rahul", "quantity": 7 },
      { "name": "Mr. Sharma", "quantity": 1 }
    ],
    "9988776655": [
      { "name": "Priya Singh", "quantity": 2 },
      { "name": "Priya", "quantity": 6 }
    ]
  }
}
EOF

    # 4) lib/on_install.dart
    cat > "$target_dir/lib/on_install.dart" <<'EOF'
Future<void> onInstall() async {
  // This function is called when the database is installed.
}
EOF

    # 5) lib/on_fetch_contacts.dart
    cat > "$target_dir/lib/on_fetch_contacts.dart" <<'EOF'
import 'dart:convert';
import 'dart:io';

import 'package:infgety_database/infgety_database.dart';

Future<List<ContactName>> onFetchContacts({
  required String regionCode,
  required String countryCode,
  required String nationalNumber,
}) async {
  final db = File('db.json');
  if (!await db.exists()) return [];

  final jsonString = await db.readAsString();
  final Map<String, dynamic> data = jsonDecode(jsonString);

  final List? contactsList = data[regionCode]?[nationalNumber];
  if (isNull(contactsList)) return [];

  return contactsList!
      .map(
        (item) => ContactName(
          name: item['name'] as String,
          quantity: item['quantity'] as int,
        ),
      )
      .toList();
}
EOF

    # 6) l10n/en.arb
    cat > "$target_dir/l10n/en.arb" <<'EOF'
{
  "@@locale": "en",
  "name": "TestDirectory",
  "description": "Test version of a random phone directory"
}
EOF

    # 7) pubspec.yaml – preserve name & sdk from the generated file
    local orig_pub="$target_dir/pubspec.yaml"
    local sdk=$(grep 'sdk:' "$orig_pub" | sed 's/^[[:space:]]*sdk:[[:space:]]*//')

    cat > "$orig_pub" <<EOF
name: database
version: 1.0.0
publish_to: none

environment:
  sdk: $sdk

dependencies:
  infgety_database:
    git:
      url: https://github.com/PSHTeam/infgety_database.git

infgety:
  identifier: $identifier
  version: 1.0.0+1
EOF

    if [[ "$VERBOSE" == true ]]; then
        log_verbose "Created pubspec.yaml with identifier '$identifier'"
        dart pub get --directory "$target_dir" || {
            log_error "Failed to run 'dart pub get'. Do you have the Dart SDK installed?"
            exit 1
        }
    else
        dart pub get --directory "$target_dir" >/dev/null 2>&1 || {
            log_error "Failed to run 'dart pub get'. Do you have the Dart SDK installed?"
            exit 1
        }
    fi

    rm -rif "$target_dir/CHANGELOG.md" "$target_dir/.gitignore" "$target_dir/analysis_options.yaml" "$target_dir/test"

    log_success "✔ Database template created at $target_dir" 
}

# =============================================================================
# MAIN SCRIPT
# =============================================================================

# Initialize variables
KEY=""
IV=""
KEY_IS_HEX=true  # Default to hex format
RECURSIVE=true
VERBOSE=false
QUIET=false

# Command-specific variables
COMMAND=""
TARGET_FILE=""
TARGET_DIR=""
DATABASE_PATH=""
DATABASE_ID=""
ENCRYPT_ARCHIVE=false
SIGN_FILES=false
OUTPUT_DIR="."
TEMPLATE=""

# Archive encryption variables
ARCHIVE_KEY=""
ARCHIVE_IV=""

# Check if any arguments provided
if [[ $# -eq 0 ]]; then
    show_usage
    exit 1
fi

# Parse command
COMMAND="$1"
shift

case "$COMMAND" in
    encrypt)
        # Parse encrypt command arguments
        while [[ $# -gt 0 ]]; do
            case $1 in
                --file)
                    TARGET_FILE="$2"
                    shift 2
                    ;;
                --dir)
                    TARGET_DIR="$2"
                    shift 2
                    ;;
                --key)
                    KEY="$2"
                    shift 2
                    ;;
                --iv)
                    IV="$2"
                    shift 2
                    ;;
                --key-format)
                    case "$2" in
                        hex)
                            KEY_IS_HEX=true
                            ;;
                        utf8)
                            KEY_IS_HEX=false
                            ;;
                        *)
                            log_error "Error: Invalid key format. Use 'hex' or 'utf8'"
                            exit 1
                            ;;
                    esac
                    shift 2
                    ;;
                --recursive)
                    RECURSIVE=true
                    shift
                    ;;
                --no-recursive)
                    RECURSIVE=false
                    shift
                    ;;
                --verbose)
                    VERBOSE=true
                    shift
                    ;;
                -h|--help)
                    echo "Infgety CLI - Encrypt Command"
                    echo ""
                    echo "Usage: $(basename "$0") encrypt [OPTIONS] --file <file> | --dir <directory>"
                    echo ""
                    echo "Description:"
                    echo "  Encrypts Dart files using AES-256-CBC encryption compatible with"
                    echo "  the Infgety Database class decryption format."
                    echo ""
                    echo "Options:"
                    echo "  --file <file>         Encrypt a single Dart file"
                    echo "  --dir <directory>     Encrypt all .dart files in directory"
                    echo "  --key <key>           Encryption key (32 UTF-8 chars or 64 hex chars) [REQUIRED]"
                    echo "  --iv <iv>             Initialization vector (32 hex characters) [REQUIRED]"
                    echo "  --key-format <fmt>    Key format: 'hex' or 'utf8' (default: hex)"
                    echo "  --recursive           Process directories recursively (default: true)"
                    echo "  --no-recursive        Don't process subdirectories"
                    echo "  --verbose             Show detailed output"
                    echo "  -h, --help            Show this help message"
                    echo ""
                    echo "Examples:"
                    echo "  $(basename "$0") encrypt --file myfile.dart --key 47BFE5FC... --iv 705179B5..."
                    echo "  $(basename "$0") encrypt --dir ./lib --key 47BFE5FC... --iv 705179B5..."
                    echo "  $(basename "$0") encrypt --dir ./src --no-recursive --key mykey --iv myiv --key-format utf8"
                    echo "  $(basename "$0") encrypt --file test.dart --verbose --key 47BFE5FC... --iv 705179B5..."
                    echo ""
                    echo "Key Formats:"
                    echo "  UTF-8:  32 characters (e.g., 'my32characterencryptionkey123456')"
                    echo "  Hex:    64 hex characters (e.g., '0123456789abcdef...')"
                    exit 0
                    ;;
                *)
                    log_error "Error: Unknown encrypt option $1"
                    echo ""
                    echo "Use '$(basename "$0") encrypt --help' for usage information."
                    exit 1
                    ;;
            esac
        done
        
        # Validate encrypt command arguments
        if [[ -z "$TARGET_FILE" && -z "$TARGET_DIR" ]]; then
            log_error "Error: Either --file or --dir must be specified for encrypt command"
            echo ""
            echo "Use '$(basename "$0") encrypt --help' for usage information."
            exit 1
        fi
        
        if [[ -n "$TARGET_FILE" && -n "$TARGET_DIR" ]]; then
            log_error "Error: Cannot specify both --file and --dir"
            exit 1
        fi
        
        # Validate required encryption parameters
        if [[ -z "$KEY" ]]; then
            log_error "Error: --key is required for encrypt command"
            echo ""
            echo "Use '$(basename "$0") encrypt --help' for usage information."
            exit 1
        fi
        
        if [[ -z "$IV" ]]; then
            log_error "Error: --iv is required for encrypt command"
            echo ""
            echo "Use '$(basename "$0") encrypt --help' for usage information."
            exit 1
        fi
        ;;
        
    archive)
        # Parse archive command arguments
        while [[ $# -gt 0 ]]; do
            case $1 in
                --database)
                    DATABASE_PATH="$2"
                    shift 2
                    ;;
                --id)
                    DATABASE_ID="$2"
                    shift 2
                    ;;
                --output)
                    OUTPUT_DIR="$2"
                    shift 2
                    ;;
                --encrypt)
                    ENCRYPT_ARCHIVE=true
                    shift
                    ;;
                --sign)
                    SIGN_FILES=true
                    shift
                    ;;
                --verbose)
                    VERBOSE=true
                    shift
                    ;;
                -h|--help)
                    echo "Infgety CLI - Archive Command"
                    echo ""
                    echo "Usage: $(basename "$0") archive [OPTIONS] --database <path> [--id <id>]"
                    echo ""
                    echo "Description:"
                    echo "  Creates a database archive (.zip) for distribution in the Infgety app"
                    echo "  ecosystem. Validates database structure and optionally encrypts Dart files"
                    echo "  using randomly generated keys that are RSA-encrypted for security."
                    echo ""
                    echo "Options:"
                    echo "  --database <path>     Path to database directory"
                    echo "  --id <id>             Database identifier (e.g., com.example.mydb)"
                    echo "  --output <dir>        Output directory for archive (default: current dir)"
                    echo "  --encrypt             Encrypt Dart files with random keys before archiving"
                    echo "  --sign                Generate SHA-256 signatures for files (use with --encrypt)"
                    echo "  --verbose            Show detailed output"
                    echo "  -h, --help           Show this help message"
                    echo ""
                    echo "Examples:"
                    echo "  $(basename "$0") archive --database ./my_database"
                    echo "  $(basename "$0") archive --database ./db --id com.example.test"
                    echo "  $(basename "$0") archive --database ./db --encrypt"
                    echo "  $(basename "$0") archive --database ./db --encrypt --sign"
                    echo "  $(basename "$0") archive --database ./db --output ./dist"
                    echo ""
                    echo "Encryption Security:"
                    echo "  When --encrypt is used, the tool generates random AES-256 keys and IVs"
                    echo "  that are saved as 'infgety_keys.json' in the database root directory."
                    echo "  These keys are RSA-encrypted and included in the archive as"
                    echo "  'infgety_keys.json.enc' for the Infgety app to decrypt."
                    echo ""
                    echo "  The unencrypted keys remain in the database directory so developers"
                    echo "  can decrypt their own files. Encrypted .enc files are automatically"
                    echo "  cleaned up after archiving. If keys already exist, they are reused."
                    echo ""
                    echo "File Signatures:"
                    echo "  When --sign is used with --encrypt, the tool generates SHA-256 signatures"
                    echo "  for all encrypted Dart files (.enc), .arb files, pubspec.yaml, and"
                    echo "  README.md (if present). Signatures are encrypted and stored as"
                    echo "  'infgety_signatures.json.enc' to prevent unauthorized modifications."
                    echo ""
                    echo "Database Structure Requirements:"
                    echo "  Required: bin/, lib/, l10n/ (with .arb files), pubspec.yaml"
                    echo "  Optional: README.md"
                    echo ""
                    echo "Note:"
                    echo "  If --id is not specified, the tool will attempt to extract"
                    echo "  the identifier from pubspec.yaml (infgety.identifier or name field)."
                    exit 0
                    ;;
                *)
                    log_error "Error: Unknown archive option $1"
                    echo ""
                    echo "Use '$(basename "$0") archive --help' for usage information."
                    exit 1
                    ;;
            esac
        done
        
        # Validate archive command arguments
        if [[ -z "$DATABASE_PATH" ]]; then
            log_error "Error: --database must be specified for archive command"
            echo ""
            echo "Use '$(basename "$0") archive --help' for usage information."
            exit 1
        fi
        
        # Validate sign requires encrypt
        if [[ "$SIGN_FILES" == true && "$ENCRYPT_ARCHIVE" != true ]]; then
            log_error "Error: --sign requires --encrypt"
            echo ""
            echo "Use '$(basename "$0") archive --help' for usage information."
            exit 1
        fi
        ;;

      create)
        # parse: infgety-cli create --template database <dir>
        while [[ $# -gt 0 ]]; do
            case $1 in
                --template)
                    TEMPLATE="$2"
                    shift 2
                    ;;
                --output)
                    TARGET_DIR="$2"
                    shift 2
                    ;;
                --id)
                    DATABASE_ID="$2"
                    shift 2
                    ;;
                -h|--help)
                    echo "Infgety CLI - Create Command"
                    echo ""
                    echo "Usage: $(basename "$0") create [OPTIONS]"
                    echo ""
                    echo "Description:"
                    echo "  Creates a new project from a built-in template."
                    echo ""
                    echo "Options:"
                    echo "  --template <name>     Template name (e.g., 'database') [REQUIRED]"
                    echo "  --output <dir>        Output directory for the new project [REQUIRED]"
                    echo "  --id <identifier>     Database identifier (e.g., com.example.mydb) [REQUIRED]"
                    echo "  --verbose             Show detailed output"
                    echo "  -h, --help            Show this help message"
                    echo ""
                    echo "Examples:"
                    echo "  $(basename "$0") create --template database --output ./my_database --id com.example.my_database"
                    exit 0
                    ;;
                *)
                    log_error "Error: Unknown create option $1"
                    echo ""
                    echo "Use '$(basename "$0") create --help' for usage information."
                    exit 1
                    ;;
            esac
        done

        if [[ -z "$TEMPLATE" || -z "$TARGET_DIR" ]]; then
            log_error "Error: --template and output directory must be specified"
            echo ""
            echo "Use '$(basename "$0") create --help' for usage information."
            exit 1
        fi
        if [[ -z "$DATABASE_ID" ]]; then
            log_error "Error: --id must be specified for create command"
            echo ""
            echo "Use '$(basename "$0") create --help' for usage information."
            exit 1
        fi
        ;;
        
    help|--help|-h)
        show_usage
        exit 0
        ;;
        
    *)
        log_error "Error: Unknown command '$COMMAND'"
        echo ""
        echo "Available commands:"
        echo "  encrypt    Encrypt Dart files"
        echo "  archive    Create database archive"
        echo "  create     Create a new project from a template"
        echo "  help       Show help message"
        echo ""
        echo "Use '$(basename "$0") --help' for full usage information."
        exit 1
        ;;
esac

# Validate key and IV (only for encrypt command)
if [[ "$COMMAND" == "encrypt" ]]; then
    if [[ "$KEY_IS_HEX" == true ]]; then
        if ! is_valid_hex_key "$KEY"; then
            log_error "Error: Hex key must be exactly 64 hexadecimal characters"
            exit 1
        fi
    else
        if ! is_valid_utf8_key "$KEY"; then
            log_error "Error: UTF-8 key must be exactly 32 characters"
            exit 1
        fi
    fi

    if ! is_valid_hex_iv "$IV"; then
        log_error "Error: IV must be exactly 32 hexadecimal characters"
        exit 1
    fi
fi

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    log_error "Error: OpenSSL is not installed or not in PATH"
    log_error "Please install OpenSSL to use this tool"
    exit 1
fi

# Check if jq is available (needed for JSON handling)
if ! command -v jq &> /dev/null; then
    log_error "Error: jq is not installed or not in PATH"
    log_error "Please install jq to use archive encryption features"
    log_error "On macOS: brew install jq"
    log_error "On Ubuntu/Debian: apt-get install jq"
    exit 1
fi

# Check if shasum is available (needed for signature generation)
if [[ "$SIGN_FILES" == true ]] && ! command -v shasum &> /dev/null; then
    log_error "Error: shasum is not installed or not in PATH"
    log_error "Please install shasum to use signature generation features"
    log_error "On macOS: shasum is included with macOS"
    log_error "On Ubuntu/Debian: apt-get install libdigest-sha-perl"
    exit 1
fi

# Check if zip is available (needed for archive creation)
if [[ "$COMMAND" == "archive" ]] && ! command -v zip &> /dev/null; then
    log_error "Error: zip is not installed or not in PATH"
    log_error "Please install zip to create archives"
    log_error "On macOS: brew install zip"
    log_error "On Ubuntu/Debian: apt-get install zip"
    exit 1
fi

# Check if dart is available (needed for template creation)
if [[ "$COMMAND" == "create" ]] && ! command -v dart &> /dev/null; then
    log_error "Error: Dart SDK is not installed or not in PATH"
    log_error "Please install Dart SDK to use template creation features"
    log_error "On macOS: brew tap dart-lang/dart && brew install dart"
    log_error "On Ubuntu/Debian: sudo apt-get install dart"
    exit 1
fi

# Execute commands
case "$COMMAND" in
    encrypt)
        # Show configuration
        if [[ "$VERBOSE" == true ]]; then
            log_info "=== Encryption Configuration ==="
            log_info "Target file: $TARGET_FILE"
            log_info "Target directory: $TARGET_DIR"
            log_info "Key format: $([ "$KEY_IS_HEX" = true ] && echo "Hex (64 chars)" || echo "UTF-8 (32 chars)")"
            log_info "Recursive: $RECURSIVE"
            log_info "================================"
        fi
        
        if [[ -n "$TARGET_FILE" ]]; then
            # Encrypt single file
            if [[ ! -f "$TARGET_FILE" ]]; then
                log_error "Error: File '$TARGET_FILE' does not exist"
                exit 1
            fi
            
            log_info "Encrypting file: $TARGET_FILE"
            output_file="${TARGET_FILE}.enc"
            
            
            if encrypt_file "$TARGET_FILE" "$output_file" "$KEY" "$IV" "$KEY_IS_HEX"; then
                log_success "✓ Successfully encrypted '$TARGET_FILE'"
                exit 0
            else
                log_error "✗ Failed to encrypt '$TARGET_FILE'"
                exit 1
            fi
        else
            # Encrypt directory
            if [[ ! -d "$TARGET_DIR" ]]; then
                log_error "Error: Directory '$TARGET_DIR' does not exist"
                exit 1
            fi
            
            log_info "Encrypting directory: $TARGET_DIR"
            if [[ "$RECURSIVE" == true ]]; then
                log_info "Recursive mode enabled"
            fi
            
            if encrypt_directory "$TARGET_DIR" "$KEY" "$IV" "$KEY_IS_HEX" "$RECURSIVE"; then
                log_success "✓ Directory encryption completed successfully"
                exit 0
            else
                log_error "✗ Directory encryption failed"
                exit 1
            fi
        fi
        ;;
        
    archive)
        # Handle database ID extraction
        if [[ -z "$DATABASE_ID" ]]; then
            if [[ -d "$DATABASE_PATH" ]]; then
                log_info "Attempting to extract database ID from pubspec.yaml..."
                DATABASE_ID=$(get_database_identifier "$DATABASE_PATH")
                if [[ $? -ne 0 || -z "$DATABASE_ID" ]]; then
                    log_error "Error: Could not determine database ID"
                    log_error "Please specify --id or ensure pubspec.yaml contains valid identifier"
                    exit 1
                fi
                log_info "Using database ID: $DATABASE_ID"
            else
                log_error "Error: --id is required for archive command"
                exit 1
            fi
        fi
        
        # Show configuration
        if [[ "$VERBOSE" == true ]]; then
            log_info "=== Archive Configuration ==="
            log_info "Database: $DATABASE_PATH"
            log_info "Database ID: $DATABASE_ID"
            log_info "Output directory: $OUTPUT_DIR"
            log_info "Encrypt: $ENCRYPT_ARCHIVE"
            log_info "Sign files: $SIGN_FILES"
            log_info "============================="
        fi
        
        # Create archive
        if create_database_archive "$DATABASE_PATH" "$DATABASE_ID" "$OUTPUT_DIR" "$ENCRYPT_ARCHIVE" "$SIGN_FILES"; then
            log_success "✓ Database archive created successfully"
            exit 0
        else
            log_error "✗ Failed to create database archive"
            exit 1
        fi
        ;;
    create)
        # Validate target directory
        if [[ -z "$TARGET_DIR" ]]; then
            log_error "Error: Target directory must be specified for create command"
            echo ""
            echo "Use '$(basename "$0") create --help' for usage information."
            exit 1
        fi

        if [[ -d "$TARGET_DIR" ]]; then
            log_error "Error: Target directory '$TARGET_DIR' already exists"
            echo ""
            echo "Use '$(basename "$0") create --help' for usage information."
            exit 1
        fi

        # Create the template
        if create_template "$TEMPLATE" "$TARGET_DIR" "$DATABASE_ID"; then
            log_success "✔ Template created successfully at $TARGET_DIR"
            exit 0
        else
            log_error "✗ Failed to create template"
            exit 1
        fi
        ;;
esac
