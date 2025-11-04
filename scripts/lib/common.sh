#!/bin/bash

# Shared helpers for WordPress Security scripts.

if [[ -n "${WPSEC_COMMON_SH:-}" ]]; then
    return 0
fi
WPSEC_COMMON_SH=1

# Color definitions (can be overridden by caller).
: "${RED:='\033[0;31m'}"
: "${GREEN:='\033[0;32m'}"
: "${YELLOW:='\033[1;33m'}"
: "${BLUE:='\033[0;34m'}"
: "${NC:='\033[0m'}"

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Ensure the Googlebot http{} bridge file exists with the include line.
ensure_googlebot_http_include() {
    local bridge_contents="# Managed by WordPress Security with Nginx on FastPanel
# Ensures security maps are defined at http{} scope.
include $GOOGLE_HTTP_INCLUDE;
include $SECURITY_HTTP_MAP;
"
    mkdir -p /etc/nginx/conf.d

    if [[ -f "$GOOGLE_HTTP_BRIDGE" ]] && cmp -s <(printf "%s" "$bridge_contents") "$GOOGLE_HTTP_BRIDGE"; then
        print_status "HTTP bridge already up to date at $GOOGLE_HTTP_BRIDGE"
        return 0
    fi

    printf "%s" "$bridge_contents" > "$GOOGLE_HTTP_BRIDGE"
    chmod 644 "$GOOGLE_HTTP_BRIDGE"
    print_success "Updated HTTP bridge at $GOOGLE_HTTP_BRIDGE"
}

wpsec_strip_security_include() {
    local vhost="$1"
    sed -i '/include \/etc\/nginx\/fastpanel2-includes\/\*\.conf;/d' "$vhost"
    sed -i '/# load security includes early/d' "$vhost"
}

wpsec_vhost_has_security_include() {
    local vhost="$1"
    grep -q 'include /etc/nginx/fastpanel2-includes/\*.conf;' "$vhost"
}

wpsec_insert_security_include() {
    local vhost="$1"
    if grep -q 'disable_symlinks if_not_owner from=\$root_path;' "$vhost"; then
        sed -i '/disable_symlinks if_not_owner from=\$root_path;/a\
    # load security includes early\
    include /etc/nginx/fastpanel2-includes/*.conf;' "$vhost"
        return 0
    fi
    return 1
}

wpsec_insert_security_include_fallback() {
    local vhost="$1"
    if grep -q 'listen.*443' "$vhost"; then
        sed -i '/listen.*443/a\
    # load security includes early\
    include /etc/nginx/fastpanel2-includes/*.conf;' "$vhost"
        return 0
    fi
    return 1
}
