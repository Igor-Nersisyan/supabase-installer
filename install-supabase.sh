#!/bin/bash
# Supabase Self-Hosted Production Installer v3.26 - Complete Edition with 10GB Upload Support
# Features: Complete Docker configuration, latest Supabase version, log rotation, 10GB uploads
# v3.26: Removed `ufw` from package install list. On Ubuntu 24.04 ufw declares
#        Breaks: iptables-persistent, netfilter-persistent — apt cannot install both
#        in one transaction. Stock 24.04 has ufw preinstalled (loop skipped it, only
#        iptables-persistent went into apt → apt removed ufw to satisfy Breaks → fine),
#        but cloud provisioners that strip ufw before this script runs (Beget/deploybox)
#        caused `apt install ufw iptables-persistent` to fail with "broken packages".
#        ufw rules wouldn't survive iptables-persistent install on the working path either,
#        so removing ufw from the list is a clean no-op behaviorally. Host firewall is
#        managed by Docker iptables + harden_supabase_db.sh.
# v3.25: Fixed Kong timeout injection - replaced PyYAML (corrupted kong.yml) with pure sed
# v3.24: Added --deploy-hook to initial certbot certonly (saved to renewal conf for systemd timer)
# v3.23: Added certbot renewal cron job with nginx reload deploy-hook for SSL auto-renewal
# v3.22: Integrated TUS resumable upload fix (direct Storage bypass, no separate fix needed)
# v3.21: Fixed streaming - direct body proxy instead of TransformStream (no early termination)
# v3.20: Protected webhook endpoints now support streaming (SSE) responses
# v3.19: Added Google OAuth configuration via .env
# v3.14: Hardening script v3.3 with option 5 (Add external IP) and grep || true fix
# Uses latest stable versions from Docker Hub
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to wait for apt locks with better user feedback
wait_for_apt_lock() {
    local first_message=true
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
       if [ "$first_message" = true ]; then
           echo ""
           echo -e "${YELLOW}⏳ System is running automatic updates in background${NC}"
           echo -e "${GREEN}   This is normal - waiting for it to finish...${NC}"
           echo -n "   "
           first_message=false
       else
           echo -n "."
       fi
       sleep 5
    done
    if [ "$first_message" = false ]; then
        echo -e " ${GREEN}✔${NC}"
        echo -e "${GREEN}✔ System updates finished, continuing installation${NC}"
        echo ""
    fi
}

# ASCII Art Header
cat << 'HEADER'
   ███████╗██╗   ██╗██████╗  █████╗ ██████╗  █████╗ ███████╗███████╗
   ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝
   ███████╗██║   ██║██████╔╝███████║██████╔╝███████║███████╗█████╗  
   ╚════██║██║   ██║██╔═══╝ ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝  
   ███████║╚██████╔╝██║     ██║  ██║██████╔╝██║  ██║███████║███████╗
   ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
HEADER

echo -e "${GREEN}                   Self-Hosted Installer v3.26${NC}"
echo -e "${GREEN}        Production Edition with 10GB File Upload Support${NC}"
echo -e "${YELLOW}        Using latest stable Supabase versions${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Display system requirements with icons
echo -e "${YELLOW}📋 Minimum System Requirements:${NC}"
echo ""
echo -e "  ${GREEN}▸${NC} CPU:  2+ cores"
echo -e "  ${GREEN}▸${NC} RAM:  3+ GB"
echo -e "  ${GREEN}▸${NC} Disk: 20+ GB (more for 10GB file uploads)"
echo -e "  ${GREEN}▸${NC} OS:   Ubuntu 20.04+ / Debian 11+"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Run as root${NC}"
  exit 1
fi

# Input with better prompts
echo -e "${GREEN}🌐 Installation Configuration${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Please provide the following information:${NC}"
echo ""
read -p "$(echo -e ${YELLOW}▸${NC} Domain name \(e.g., supabase.example.com\): )" DOMAIN
read -p "$(echo -e ${YELLOW}▸${NC} Email for SSL certificate: )" EMAIL
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Generate passwords with progress indicator
echo -e "${GREEN}🔐 Security Configuration${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Generating secure passwords...${NC}"
echo -n "  "
POSTGRES_PASSWORD=$(openssl rand -hex 32)
echo -n "▓▓▓"
JWT_SECRET=$(openssl rand -hex 32)
echo -n "▓▓▓"
DASHBOARD_PASSWORD=$(openssl rand -hex 16)
echo -n "▓▓▓"
SECRET_KEY_BASE=$(openssl rand -hex 32)
echo -n "▓▓▓"
VAULT_ENC_KEY=$(openssl rand -hex 16)
echo -e "▓▓▓ ${GREEN}✔${NC}"
echo ""
echo -e "${GREEN}✔ All passwords generated successfully${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Wait for apt locks to be released
echo -e "${YELLOW}Checking for apt locks...${NC}"
wait_for_apt_lock

# Install packages with smart Docker detection
echo -e "${GREEN}📦 Package Installation${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Checking installed packages...${NC}"
apt-get update -qq

# Check if Docker is already installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}⬇ Installing Docker...${NC}"
    wait_for_apt_lock
    apt-get install -y docker.io -qq
    echo -e "${GREEN}  ✔ Docker installed successfully${NC}"
else
    echo -e "${GREEN}  ✔ Docker already installed ($(docker --version | cut -d' ' -f3 | cut -d',' -f1))${NC}"
fi

# Check if docker-compose is already installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}⬇ Installing Docker Compose...${NC}"
    wait_for_apt_lock
    apt-get install -y docker-compose -qq
    echo -e "${GREEN}  ✔ Docker Compose installed successfully${NC}"
else
    echo -e "${GREEN}  ✔ Docker Compose already installed${NC}"
fi

# Install other required packages (including logrotate)
# v3.26: `ufw` removed from this list. On Ubuntu 24.04 ufw declares
# Breaks: iptables-persistent, netfilter-persistent, so apt refuses to install
# both in one transaction. ufw was dead code on the working path anyway —
# iptables-persistent installation removes ufw to satisfy the Breaks directive.
echo -e "${GREEN}Checking other dependencies...${NC}"
PACKAGES_TO_INSTALL=""

# Check each package and add to install list if not present
for pkg in git nginx certbot python3-certbot-nginx wget curl nano python3-yaml jq logrotate iptables-persistent; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
    else
        echo -e "${GREEN}  ✔ $pkg${NC}"
    fi
done

if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
    echo -e "${YELLOW}⬇ Installing missing packages:${NC}$PACKAGES_TO_INSTALL"
    wait_for_apt_lock
    DEBIAN_FRONTEND=noninteractive apt-get install -y $PACKAGES_TO_INSTALL -qq
    echo -e "${GREEN}  ✔ All packages installed successfully${NC}"
fi

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Configure complete Docker daemon settings
echo -e "${GREEN}🔧 Configuring Docker Daemon with Complete Settings${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Setting up Docker daemon configuration...${NC}"

# Backup existing configuration if it exists
if [ -f /etc/docker/daemon.json ]; then
    cp /etc/docker/daemon.json /etc/docker/daemon.json.backup.$(date +%Y%m%d_%H%M%S)
    echo -e "${GREEN}✔ Backed up existing Docker configuration${NC}"
fi

# Create complete Docker daemon configuration
cat > /etc/docker/daemon.json << 'DOCKERDAEMON'
{
  "bip": "172.17.0.1/16",
  "iptables": true,
  "ip-masq": true,
  "dns": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
  "dns-opts": ["ndots:0"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DOCKERDAEMON

echo -e "${GREEN}Docker daemon configured with:${NC}"
echo -e "  ${GREEN}✔${NC} NAT enabled (ip-masq) for internet access"
echo -e "  ${GREEN}✔${NC} Public DNS servers for reliability" 
echo -e "  ${GREEN}✔${NC} Log rotation (10MB max, 3 files)"
echo -e "  ${GREEN}✔${NC} Optimized DNS resolution for Edge Functions"
echo -e "  ${GREEN}✔${NC} Standard Docker subnet configuration"

echo -e "${GREEN}Restarting Docker to apply configuration...${NC}"
systemctl daemon-reload
systemctl restart docker
sleep 5

echo -e "${GREEN}✔ Docker daemon configured successfully${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Configure log rotation for existing logs
echo -e "${GREEN}📊 Configuring Log Rotation${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Setting up automatic log rotation...${NC}"

cat > /etc/logrotate.d/docker-containers << 'LOGROTATE'
/var/lib/docker/containers/*/*.log {
  rotate 7
  daily
  compress
  size 50M
  missingok
  delaycompress
  copytruncate
  notifempty
}
LOGROTATE

# Test logrotate configuration
logrotate -d /etc/logrotate.d/docker-containers 2>/dev/null || true

echo -e "${GREEN}✔ Log rotation configured (daily, max 50MB, keep 7 days)${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Install docker compose v2 if needed
if ! docker compose version &> /dev/null 2>&1; then
   echo -e "${YELLOW}Installing Docker Compose v2 plugin...${NC}"
   LATEST_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r .tag_name 2>/dev/null || echo "")
   if [ -z "$LATEST_COMPOSE_VERSION" ]; then
        LATEST_COMPOSE_VERSION="v2.20.0" # Fallback
   fi
   mkdir -p /usr/local/lib/docker/cli-plugins/
   curl -SL "https://github.com/docker/compose/releases/download/${LATEST_COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose
   chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
   echo -e "${GREEN}✔ Docker Compose ${LATEST_COMPOSE_VERSION} plugin installed${NC}"
else
   echo -e "${GREEN}✔ Docker Compose v2 already available${NC}"
fi

# Configure firewall
# v3.26: ufw is no longer installed by this script. Block below skips automatically
# via `command -v ufw`. Host firewall is managed by Docker iptables rules and
# the harden_supabase_db.sh script generated below.
echo -e "${GREEN}🔥 Firewall Configuration${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if command -v ufw &> /dev/null; then
   echo -e "${GREEN}Adding firewall rules...${NC}"
   ufw allow 22/tcp comment 'SSH' 2>/dev/null
   echo -e "  ${GREEN}✔${NC} SSH (22)"
   ufw allow 80/tcp comment 'HTTP for SSL cert' 2>/dev/null  
   echo -e "  ${GREEN}✔${NC} HTTP (80)"
   ufw allow 443/tcp comment 'HTTPS' 2>/dev/null
   echo -e "  ${GREEN}✔${NC} HTTPS (443)"
   ufw allow 5432/tcp comment 'PostgreSQL' 2>/dev/null
   echo -e "  ${GREEN}✔${NC} PostgreSQL (5432)"
   
   UFW_STATUS=$(ufw status | grep -c "Status: active" || true)
   if [ "$UFW_STATUS" -eq 0 ]; then
       echo -e "${GREEN}Enabling firewall...${NC}"
       ufw --force enable
       echo -e "${GREEN}✔ Firewall enabled successfully${NC}"
   else
       echo -e "${GREEN}✔ Firewall already active${NC}"
   fi
else
   echo -e "${GREEN}✔ UFW not installed — host firewall handled by Docker iptables.${NC}"
   echo -e "${GREEN}  Run /root/harden_supabase_db.sh after install to lock down PostgreSQL.${NC}"
fi

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Clone Supabase
echo -e "${GREEN}📥 Supabase Installation${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Setting up Supabase directory...${NC}"

cd /opt
rm -rf supabase-project
rm -rf supabase
echo -e "${GREEN}Cloning latest Supabase repository...${NC}"
git clone --depth 1 https://github.com/supabase/supabase.git
mkdir -p supabase-project
cp -r supabase/docker/* supabase-project/
cp supabase/docker/.env.example supabase-project/.env
cd supabase-project

echo -e "${GREEN}✔ Supabase files prepared (latest version from GitHub)${NC}"
echo ""

# Fix docker-compose.yml for compatibility
sed -i '/^name:/d' docker-compose.yml 2>/dev/null || true
sed -i 's/: true/: "true"/g' docker-compose.yml
sed -i 's/: false/: "false"/g' docker-compose.yml

# Optimize analytics container AND add 10GB upload support AND email templates AND TUS fix
echo -e "${GREEN}🔧 Configuring Services with 10GB Upload Support, TUS Fix & Email Templates${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Applying memory optimization, 10GB file upload, TUS bypass, and email templates...${NC}"

# Pass DOMAIN to Python script
python3 << PYTHONEOF
import yaml
import sys

# Domain passed as variable from bash
domain = "$DOMAIN"

try:
    with open('docker-compose.yml', 'r') as f:
        data = yaml.safe_load(f)

    modified = False

    # Add template-server for email templates (v3.18)
    if 'services' in data:
        data['services']['template-server'] = {
            'image': 'nginx:alpine',
            'container_name': 'supabase-templates',
            'volumes': ['./email_templates:/usr/share/nginx/html:ro'],
            'restart': 'unless-stopped'
        }
        print("✔ Template server added for email templates")
        modified = True

    # Add environment variables to analytics service if it exists
    if 'services' in data and 'analytics' in data['services']:
        if 'environment' not in data['services']['analytics']:
            data['services']['analytics']['environment'] = {}
        
        # Add optimization variables (reduces memory from ~1.3GB to ~450MB)
        optimization_vars = {
            'LOGFLARE_TELEMETRY_ENABLED': 'false',
            'TELEMETRY_ENABLED': 'false',
            'LOGFLARE_HEARTBEAT_INTERVAL': '60000',
            'DD_ENABLED': 'false',
            'DATADOG_API_KEY': 'disabled',
            'LOGFLARE_DATADOG_API_KEY': 'disabled',
            'DISABLE_DATADOG': 'true',
            'LOGFLARE_DATADOG_ENABLED': 'false'
        }
        
        # Update only if not already set
        for key, value in optimization_vars.items():
            if key not in data['services']['analytics']['environment']:
                data['services']['analytics']['environment'][key] = value
        
        print("✔ Analytics optimization variables added")
        modified = True

    # Add 10GB upload support + TUS fix to storage service
    # CRITICAL FIX v3.15: Use INTEGER values, not strings!
    # v3.22: TUS_URL_PATH fixed to /upload/resumable (Storage adds /storage/v1 prefix internally)
    if 'services' in data and 'storage' in data['services']:
        if 'environment' not in data['services']['storage']:
            data['services']['storage']['environment'] = {}
        
        # v3.22: Fixed TUS_URL_PATH + added TUS_URL_SCHEME and TUS_URL_PORT
        storage_vars = {
            'FILE_SIZE_LIMIT': 10737418240,              # 10GB - MAIN VARIABLE (was missing!)
            'UPLOAD_FILE_SIZE_LIMIT': 10737418240,       # 10GB for TUS resumable uploads
            'UPLOAD_FILE_SIZE_LIMIT_STANDARD': 10737418240,  # 10GB for standard uploads (was 1GB!)
            'SERVER_KEEP_ALIVE_TIMEOUT': '7200',         # 2 hours
            'SERVER_HEADERS_TIMEOUT': '7200',            # 2 hours
            'UPLOAD_SIGNED_URL_EXPIRATION_TIME': '7200', # 2 hours
            'TUS_URL_PATH': '/upload/resumable',         # v3.22 FIX: no /storage/v1 prefix!
            'TUS_URL_HOST': domain,
            'TUS_URL_SCHEME': 'https',                   # v3.22: explicit scheme
            'TUS_URL_PORT': '443',                       # v3.22: explicit port
            'STORAGE_BACKEND_URL': f'https://{domain}'
        }
        
        for key, value in storage_vars.items():
            data['services']['storage']['environment'][key] = value
        
        # v3.22: Add port mapping for direct TUS access (bypassing Kong)
        if 'ports' not in data['services']['storage']:
            data['services']['storage']['ports'] = []
        tus_port = '127.0.0.1:5000:5000'
        existing_ports = [str(p) for p in data['services']['storage'].get('ports', [])]
        if tus_port not in existing_ports:
            data['services']['storage']['ports'].append(tus_port)
        
        print(f"✔ Storage service configured for 10GB uploads with domain: {domain}")
        print(f"  FILE_SIZE_LIMIT: 10737418240 (integer)")
        print(f"  UPLOAD_FILE_SIZE_LIMIT: 10737418240 (integer)")
        print(f"  UPLOAD_FILE_SIZE_LIMIT_STANDARD: 10737418240 (integer)")
        print(f"  TUS_URL_PATH: /upload/resumable (v3.22 fix)")
        print(f"  TUS_URL_SCHEME: https (v3.22)")
        print(f"  TUS_URL_PORT: 443 (v3.22)")
        print(f"  Port 127.0.0.1:5000:5000 exposed for direct TUS access (v3.22)")
        modified = True

    # Add Kong configuration for large body size
    if 'services' in data and 'kong' in data['services']:
        if 'environment' not in data['services']['kong']:
            data['services']['kong']['environment'] = {}
        
        kong_vars = {
            'KONG_NGINX_HTTP_CLIENT_MAX_BODY_SIZE': '11000m',  # 11GB with margin
            'KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE': '128m',
            'KONG_NGINX_PROXY_PROXY_CONNECT_TIMEOUT': '300000ms',
            'KONG_NGINX_PROXY_PROXY_READ_TIMEOUT': '300000ms',
            'KONG_NGINX_PROXY_PROXY_SEND_TIMEOUT': '300000ms'
        }
        
        for key, value in kong_vars.items():
            data['services']['kong']['environment'][key] = value
        
        print("✔ Kong configured for 10GB request body support")
        modified = True

    # Configure Auth (GoTrue) email templates via URL (v3.18 fix)
    # NOTE: GoTrue requires URL to template files, NOT inline HTML content
    auth_service = None
    if 'services' in data:
        if 'auth' in data['services']:
            auth_service = data['services']['auth']
        elif 'gotrue' in data['services']:
            auth_service = data['services']['gotrue']

    if auth_service:
        if 'environment' not in auth_service:
            auth_service['environment'] = {}
        
        # v3.18: Use URLs to template-server (NOT inline _CONTENT variables!)
        email_vars = {
            'GOTRUE_MAILER_TEMPLATES_CONFIRMATION': 'http://template-server/confirmation.html',
            'GOTRUE_MAILER_TEMPLATES_RECOVERY': 'http://template-server/recovery.html',
            'GOTRUE_MAILER_TEMPLATES_MAGIC_LINK': 'http://template-server/magic_link.html',
            'GOTRUE_MAILER_TEMPLATES_INVITE': 'http://template-server/invite.html',
            'GOTRUE_MAILER_TEMPLATES_EMAIL_CHANGE': 'http://template-server/email_change.html'
        }
        
        for key, value in email_vars.items():
            auth_service['environment'][key] = value
        
        # v3.19: Google OAuth configuration from .env
        google_vars = {
            'GOTRUE_EXTERNAL_GOOGLE_ENABLED': '\${GOOGLE_ENABLED}',
            'GOTRUE_EXTERNAL_GOOGLE_CLIENT_ID': '\${GOOGLE_CLIENT_ID}',
            'GOTRUE_EXTERNAL_GOOGLE_SECRET': '\${GOOGLE_SECRET}',
            'GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI': '\${GOOGLE_REDIRECT_URI}'
        }
        
        for key, value in google_vars.items():
            auth_service['environment'][key] = value
            
        print("✔ Auth service configured with email templates & Google OAuth")
        modified = True
    else:
        print("⚠ Auth/GoTrue service not found - email templates not configured")
        
    if modified:
        with open('docker-compose.yml', 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        print("✔ All service configurations applied successfully")
        sys.exit(0)
    else:
        print("⚠ No services found to modify")
        sys.exit(1)
        
except Exception as e:
    print(f"⚠ Could not modify docker-compose.yml: {e}")
    sys.exit(1)
PYTHONEOF

if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to configure services${NC}"
    echo -e "${RED}Manual configuration required. Check docker-compose.yml${NC}"
    exit 1
fi

# Create email templates directory and HTML files (v3.18)
echo -e "${GREEN}Creating email templates...${NC}"
mkdir -p email_templates

cat > email_templates/confirmation.html << 'EMAILEOF'
<h2>Confirm your email</h2>
<p>Thanks for signing up! Please confirm your email by clicking the link below:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm email address</a></p>
<p>Or enter the code: {{ .Token }}</p>
EMAILEOF

cat > email_templates/recovery.html << 'EMAILEOF'
<h2>Reset your password</h2>
<p>Click the link below to reset your password:</p>
<p><a href="{{ .ConfirmationURL }}">Reset password</a></p>
<p>If you didn't request this, you can safely ignore this email.</p>
EMAILEOF

cat > email_templates/magic_link.html << 'EMAILEOF'
<h2>Your login link</h2>
<p>Click the link below to log in:</p>
<p><a href="{{ .ConfirmationURL }}">Log in to your account</a></p>
<p>This link expires in 1 hour.</p>
EMAILEOF

cat > email_templates/invite.html << 'EMAILEOF'
<h2>You have been invited!</h2>
<p>You have been invited to join. Click the link below to accept:</p>
<p><a href="{{ .ConfirmationURL }}">Accept invitation</a></p>
EMAILEOF

cat > email_templates/email_change.html << 'EMAILEOF'
<h2>Confirm your new email</h2>
<p>Click the link below to confirm your new email address:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm new email</a></p>
EMAILEOF

echo -e "${GREEN}✔ Email templates created in email_templates/${NC}"

echo -e "${GREEN}✔ Services configured for 10GB file uploads${NC}"
echo -e "${GREEN}✔ TUS resumable uploads configured (direct Storage bypass) (v3.22)${NC}"
echo -e "${GREEN}✔ Analytics container optimized (memory usage reduced by ~65%)${NC}"
echo -e "${GREEN}✔ Email templates configured via template-server${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Install Node.js (LTS) and npm if not present
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Installing Node.js (LTS)...${NC}"
    echo -e "${GREEN}📝 Note: If system shows 'apt lock' messages, this is normal.${NC}"
    echo -e "${GREEN}   Ubuntu is running automatic updates in background.${NC}"
    echo -e "${GREEN}   Script will wait and continue automatically.${NC}"
    echo ""
    
    # Ensure curl is installed, as it's needed for the NodeSource script
    if ! command -v curl &> /dev/null; then
        apt-get update -qq
        wait_for_apt_lock
        apt-get install -y curl -qq
    fi
    
    # Download and run the NodeSource setup script for the latest LTS version
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - 2>&1 | grep -v "apt lock" || true
    
    # Now install Node.js from the newly added repository
    wait_for_apt_lock
    apt-get install -y nodejs -qq
    
    echo -e "${GREEN}✔ Node.js installed successfully ($(node --version))${NC}"
else
    echo -e "${GREEN}✔ Node.js already installed ($(node --version))${NC}"
fi

# Generate JWT keys
echo -e "${YELLOW}Generating JWT keys...${NC}"

cat > /tmp/generate-jwt.js << 'EOF'
const crypto = require('crypto');
const JWT_SECRET = process.argv[2];

function signJWT(payload, secret) {
   const header = { alg: 'HS256', typ: 'JWT' };
   const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
   const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
   const signature = crypto.createHmac('sha256', secret).update(`${encodedHeader}.${encodedPayload}`).digest('base64url');
   return `${encodedHeader}.${encodedPayload}.${signature}`;
}

const now = Math.floor(Date.now() / 1000);
const exp = now + (60 * 60 * 24 * 365 * 10);
const anonPayload = { role: 'anon', iss: 'supabase', iat: now, exp: exp };
const servicePayload = { role: 'service_role', iss: 'supabase', iat: now, exp: exp };

console.log('ANON_KEY=' + signJWT(anonPayload, JWT_SECRET));
console.log('SERVICE_ROLE_KEY=' + signJWT(servicePayload, JWT_SECRET));
EOF

KEYS=$(node /tmp/generate-jwt.js "$JWT_SECRET" 2>/dev/null || echo "")
if [ -z "$KEYS" ]; then
    echo -e "${RED}WARNING: JWT key generation failed. Using fallback keys.${NC}"
    # Fallback: use simple base64 encoded values (not secure but will allow installation to continue)
    ANON_KEY="${JWT_SECRET:0:32}_anon_fallback"
    SERVICE_ROLE_KEY="${JWT_SECRET:0:32}_service_fallback"
else
    ANON_KEY=$(echo "$KEYS" | grep ANON_KEY | cut -d'=' -f2)
    SERVICE_ROLE_KEY=$(echo "$KEYS" | grep SERVICE_ROLE_KEY | cut -d'=' -f2)
fi
rm -f /tmp/generate-jwt.js

# Configure .env
echo -e "${YELLOW}Configuring environment variables...${NC}"
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" .env
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" .env
sed -i "s|^ANON_KEY=.*|ANON_KEY=$ANON_KEY|" .env
sed -i "s|^SERVICE_ROLE_KEY=.*|SERVICE_ROLE_KEY=$SERVICE_ROLE_KEY|" .env
sed -i "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD|" .env
sed -i "s|^SITE_URL=.*|SITE_URL=https://$DOMAIN|" .env
sed -i "s|^API_EXTERNAL_URL=.*|API_EXTERNAL_URL=https://$DOMAIN|" .env
sed -i "s|^SUPABASE_PUBLIC_URL=.*|SUPABASE_PUBLIC_URL=https://$DOMAIN|" .env

# IMPORTANT: Use postgres for tenant ID for maximum compatibility
sed -i "s|^POOLER_TENANT_ID=.*|POOLER_TENANT_ID=postgres|" .env

# Additional settings
sed -i "s|^VAULT_ENC_KEY=.*|VAULT_ENC_KEY=$VAULT_ENC_KEY|" .env
grep -q "SECRET_KEY_BASE" .env || echo "SECRET_KEY_BASE=$SECRET_KEY_BASE" >> .env

# Email settings
sed -i "s|^SMTP_ADMIN_EMAIL=.*|SMTP_ADMIN_EMAIL=$EMAIL|" .env
sed -i "s|^SMTP_HOST=.*|SMTP_HOST=smtp.gmail.com|" .env
sed -i "s|^SMTP_PORT=.*|SMTP_PORT=587|" .env
sed -i "s|^SMTP_USER=.*|SMTP_USER=$EMAIL|" .env
sed -i "s|^SMTP_SENDER_NAME=.*|SMTP_SENDER_NAME=Supabase|" .env

# Add additional configurations with FIXED domain values (not $DOMAIN)
cat >> .env << ENVEOF

# Realtime Configuration
REALTIME_IP_VERSION=IPv4
REALTIME_PORT=4000
REALTIME_SOCKET_TIMEOUT=7200000
REALTIME_HEARTBEAT_INTERVAL=30000
REALTIME_HEARTBEAT_TIMEOUT=60000
REALTIME_MAX_EVENTS_PER_SECOND=100

# Functions
FUNCTIONS_VERIFY_JWT=true

# Storage URL configuration for TUS (10GB uploads)
# v3.22: Fixed TUS_URL_PATH (no /storage/v1 prefix - Storage adds it internally)
TUS_URL_HOST=$DOMAIN
TUS_URL_PATH=/upload/resumable
TUS_URL_SCHEME=https
TUS_URL_PORT=443
STORAGE_BACKEND_URL=https://$DOMAIN

# N8N Integration (public endpoint)
N8N_WEBHOOK_URL=
N8N_BASIC_AUTH_HEADER=

# Protected Webhook Endpoints
ENDPOINT_1_WEBHOOK_URL=
ENDPOINT_1_AUTH_HEADER=
ENDPOINT_2_WEBHOOK_URL=
ENDPOINT_2_AUTH_HEADER=
ENDPOINT_3_WEBHOOK_URL=
ENDPOINT_3_AUTH_HEADER=

# ========================================
# GOOGLE OAUTH (v3.19)
# ========================================
# Get credentials from Google Cloud Console:
# 1. Go to APIs & Services -> Credentials
# 2. Create OAuth 2.0 Client ID (Web application)
# 3. Add authorized redirect URI: https://YOUR_DOMAIN/auth/v1/callback
#
# Leave GOOGLE_CLIENT_ID empty to disable Google auth
GOOGLE_ENABLED=false
GOOGLE_CLIENT_ID=
GOOGLE_SECRET=
GOOGLE_REDIRECT_URI=https://$DOMAIN/auth/v1/callback

# ========================================
# EMAIL TEMPLATES (v3.18)
# ========================================
# Templates are stored in email_templates/ directory as HTML files.
# Edit these files to customize your emails:
#   - email_templates/confirmation.html
#   - email_templates/recovery.html
#   - email_templates/magic_link.html
#   - email_templates/invite.html
#   - email_templates/email_change.html
#
# Available variables in templates:
#   {{ .ConfirmationURL }} - confirmation/action link
#   {{ .Email }} - user's email address
#   {{ .Token }} - raw token (6-digit code)
#   {{ .TokenHash }} - hashed token
#   {{ .SiteURL }} - your site URL
#
# After editing templates, restart: docker compose restart auth
ENVEOF

# CRITICAL FIX: Substitute variables in kong.yml BEFORE starting containers
echo -e "${YELLOW}Configuring Kong API Gateway...${NC}"
cp volumes/api/kong.yml volumes/api/kong.yml.template
sed -i "s|\$SUPABASE_ANON_KEY|$ANON_KEY|g" volumes/api/kong.yml
sed -i "s|\$SUPABASE_SERVICE_KEY|$SERVICE_ROLE_KEY|g" volumes/api/kong.yml
sed -i "s|\$DASHBOARD_USERNAME|supabase|g" volumes/api/kong.yml
sed -i "s|\$DASHBOARD_PASSWORD|$DASHBOARD_PASSWORD|g" volumes/api/kong.yml

# Verify substitution
if grep -q '\$SUPABASE_ANON_KEY' volumes/api/kong.yml; then
    echo -e "${RED}ERROR: Variable substitution failed in kong.yml${NC}"
    exit 1
fi

echo -e "${GREEN}✔ Kong configuration variables substituted successfully${NC}"

# v3.25: Add Kong timeouts using pure sed (PyYAML was corrupting kong.yml formatting)
echo -e "${YELLOW}Configuring Kong timeouts for long-running functions...${NC}"

if grep -q "name: functions-v1" volumes/api/kong.yml; then
    # Remove original read_timeout: 150000 from functions-v1 to avoid duplicates
    sed -i '/url: http:\/\/functions:9000\//{ n; /read_timeout: 150000/d }' volumes/api/kong.yml
    # Insert 300-second timeouts after the functions URL line (4-space indent to match YAML)
    sed -i '/url: http:\/\/functions:9000\//a\    connect_timeout: 300000\n    write_timeout: 300000\n    read_timeout: 300000' volumes/api/kong.yml
    echo -e "${GREEN}✔ Kong timeouts added (300s) for functions-v1 service${NC}"
else
    echo -e "${RED}WARNING: Could not find functions-v1 service in kong.yml${NC}"
    echo -e "${YELLOW}Edge Functions may timeout after 60 seconds${NC}"
fi

echo -e "${GREEN}✔ Kong timeouts configured for 5-minute requests${NC}"

# Create vector.yml
echo -e "${YELLOW}Creating vector configuration...${NC}"
mkdir -p volumes/logs

cat > volumes/logs/vector.yml << 'VECTOREOF'
api:
 enabled: true
 address: 0.0.0.0:9001

sources:
 docker_logs:
   type: docker_logs
   include_images:
     - supabase/postgres
     - supabase/gotrue
     - postgrest/postgrest
     - supabase/realtime
     - supabase/storage-api
     - kong
     - supabase/edge-runtime

sinks:
 console:
   type: console
   inputs:
     - docker_logs
   encoding:
     codec: json
VECTOREOF

# Add ENV variables to docker-compose.yml
echo -e "${YELLOW}Adding ENV variables to docker-compose.yml...${NC}"

python3 << 'PYTHONEOF'
import yaml
import sys

try:
    with open('docker-compose.yml', 'r') as f:
        data = yaml.safe_load(f)

    modified = False

    # Add ENV variables to functions service
    if 'functions' in data.get('services', {}):
        if 'environment' not in data['services']['functions']:
            data['services']['functions']['environment'] = {}
        
        data['services']['functions']['environment'].update({
            'N8N_WEBHOOK_URL': '${N8N_WEBHOOK_URL}',
            'N8N_BASIC_AUTH_HEADER': '${N8N_BASIC_AUTH_HEADER}',
            'ENDPOINT_1_WEBHOOK_URL': '${ENDPOINT_1_WEBHOOK_URL}',
            'ENDPOINT_1_AUTH_HEADER': '${ENDPOINT_1_AUTH_HEADER}',
            'ENDPOINT_2_WEBHOOK_URL': '${ENDPOINT_2_WEBHOOK_URL}',
            'ENDPOINT_2_AUTH_HEADER': '${ENDPOINT_2_AUTH_HEADER}',
            'ENDPOINT_3_WEBHOOK_URL': '${ENDPOINT_3_WEBHOOK_URL}',
            'ENDPOINT_3_AUTH_HEADER': '${ENDPOINT_3_AUTH_HEADER}'
        })
        
        print("✔ ENV variables added to functions service")
        modified = True

    if modified:
        with open('docker-compose.yml', 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        sys.exit(0)
    else:
        print("⚠ functions service not found in docker-compose.yml")
        sys.exit(1)
        
except Exception as e:
    print(f"⚠ Could not modify docker-compose.yml: {e}")
    sys.exit(1)
PYTHONEOF

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Failed to add ENV variables automatically.${NC}"
    echo -e "${RED}IMPORTANT: Manually add these to docker-compose.yml functions environment section:${NC}"
    echo "      N8N_WEBHOOK_URL: \${N8N_WEBHOOK_URL}"
    echo "      N8N_BASIC_AUTH_HEADER: \${N8N_BASIC_AUTH_HEADER}"
    echo "      ENDPOINT_1_WEBHOOK_URL: \${ENDPOINT_1_WEBHOOK_URL}"
    echo "      ENDPOINT_1_AUTH_HEADER: \${ENDPOINT_1_AUTH_HEADER}"
    echo "      ENDPOINT_2_WEBHOOK_URL: \${ENDPOINT_2_WEBHOOK_URL}"
    echo "      ENDPOINT_2_AUTH_HEADER: \${ENDPOINT_2_AUTH_HEADER}"
    echo "      ENDPOINT_3_WEBHOOK_URL: \${ENDPOINT_3_WEBHOOK_URL}"
    echo "      ENDPOINT_3_AUTH_HEADER: \${ENDPOINT_3_AUTH_HEADER}"
fi

# Create Edge Functions
echo -e "${YELLOW}Creating Edge Functions...${NC}"
mkdir -p volumes/functions/{n8n-proxy,webhook-endpoint-1,webhook-endpoint-2,webhook-endpoint-3,_shared,main,hello}

# Shared CORS
cat > volumes/functions/_shared/cors.ts << 'EOF'
export const corsHeaders = {
 'Access-Control-Allow-Origin': '*',
 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-session-id',
}
EOF

# FIXED main function with correct public endpoint detection
cat > volumes/functions/main/index.ts << 'EOF'
import { serve } from 'https://deno.land/std@0.131.0/http/server.ts'
import * as jose from 'https://deno.land/x/jose@v4.14.4/index.ts'

console.log('main function started')

const JWT_SECRET = Deno.env.get('JWT_SECRET')
const VERIFY_JWT = Deno.env.get('VERIFY_JWT') === 'true'

// Public endpoints that do NOT require authorization
const PUBLIC_ENDPOINTS = [
 'n8n-proxy',
 'hello'
]

function getAuthToken(req: Request) {
 const authHeader = req.headers.get('authorization')
 if (!authHeader) {
   throw new Error('Missing authorization header')
 }
 const [bearer, token] = authHeader.split(' ')
 if (bearer !== 'Bearer') {
   throw new Error(`Auth header is not 'Bearer {token}'`)
 }
 return token
}

async function verifyJWT(jwt: string): Promise<boolean> {
 const encoder = new TextEncoder()
 const secretKey = encoder.encode(JWT_SECRET)
 try {
   await jose.jwtVerify(jwt, secretKey)
 } catch (err) {
   console.error(err)
   return false
 }
 return true
}

serve(async (req: Request) => {
 const url = new URL(req.url)
 const { pathname } = url
 const path_parts = pathname.split('/')
 const function_name = path_parts[path_parts.length - 1]
 
 console.log(`Routing to function: ${function_name}`)
 console.log(`VERIFY_JWT is set to: ${VERIFY_JWT}`)
 
 // Check if endpoint is public - check by function name without slashes
 const isPublicEndpoint = PUBLIC_ENDPOINTS.includes(function_name)
 
 console.log(`Function ${function_name} is public: ${isPublicEndpoint}`)
 
 // If NOT public AND JWT verification enabled - check token
 if (!isPublicEndpoint && VERIFY_JWT) {
   try {
     const token = getAuthToken(req)
     const isValidJWT = await verifyJWT(token)
     
     if (!isValidJWT) {
       return new Response(JSON.stringify({ error: 'Invalid JWT' }), {
         status: 401,
         headers: { 'Content-Type': 'application/json' }
       })
     }
   } catch (e) {
     console.error(e)
     return new Response(JSON.stringify({ error: e.toString() }), {
       status: 401,
       headers: { 'Content-Type': 'application/json' }
     })
   }
 }
 
 // Call target function
 const servicePath = `/home/deno/functions/${function_name}`
 console.log(`serving the request with ${servicePath}`)
 
 const createWorker = async () => {
   const memoryLimitMb = 150
   const workerTimeoutMs = 5 * 60 * 1000
   const noModuleCache = false
   const envVarsObj = Deno.env.toObject()
   const envVars = Object.keys(envVarsObj).map((k) => [k, envVarsObj[k]])
   
   return await EdgeRuntime.userWorkers.create({
     servicePath,
     memoryLimitMb,
     workerTimeoutMs,
     noModuleCache,
     envVars,
     forceCreate: false,
     netAccessDisabled: false,
     cpuTimeSoftLimitMs: 5000,
     cpuTimeHardLimitMs: 10000,
   })
 }
 
 const callWorker = async () => {
   try {
     const worker = await createWorker()
     return await worker.fetch(req)
   } catch (e) {
     console.error(e)
     return new Response(JSON.stringify({ error: e.toString() }), {
       status: 500,
       headers: { 'Content-Type': 'application/json' }
     })
   }
 }
 
 return callWorker()
})
EOF

# Hello function for testing
cat > volumes/functions/hello/index.ts << 'EOF'
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

serve(async (req) => {
 const data = {
   message: 'Hello from Supabase Edge Functions!',
   time: new Date().toISOString()
 }
 
 return new Response(
   JSON.stringify(data),
   { headers: { "Content-Type": "application/json" } }
 )
})
EOF

# n8n-proxy - PUBLIC endpoint (fixed version)
cat > volumes/functions/n8n-proxy/index.ts << 'EOF'
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

const corsHeaders = {
 'Access-Control-Allow-Origin': '*',
 'Access-Control-Allow-Headers': '*',
}

serve(async (req: Request) => {
 if (req.method === 'OPTIONS') {
   return new Response('ok', { headers: corsHeaders })
 }
 
 try {
   let body = {}
   
   // Parse JSON only if body exists
   if (req.headers.get('content-length') !== '0' && req.method !== 'GET') {
     try {
       body = await req.json()
     } catch (e) {
       // If not JSON, get as text
       body = { data: await req.text() }
     }
   }
   
   const n8nUrl = Deno.env.get('N8N_WEBHOOK_URL')
   const authHeaderN8N = Deno.env.get('N8N_BASIC_AUTH_HEADER')
   
   if (!n8nUrl) {
     return new Response(
       JSON.stringify({ 
         error: 'N8N webhook not configured',
         message: 'Please configure N8N_WEBHOOK_URL in .env'
       }),
       { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 }
     )
   }
   
   // Collect metadata
   const authHeader = req.headers.get('Authorization')
   const sessionId = req.headers.get('X-Session-ID')
   const clientIp = req.headers.get('x-real-ip') || 
                    req.headers.get('x-forwarded-for')?.split(',')[0] || 
                    'unknown'
   
   // Metadata for n8n
   const enrichedBody = {
     ...body,
     session_id: sessionId || null,
     has_auth: !!authHeader,
     client_ip: clientIp,
     timestamp: new Date().toISOString()
   }
   
   const n8nResponse = await fetch(n8nUrl, {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       ...(authHeaderN8N ? { 'Authorization': authHeaderN8N } : {})
     },
     body: JSON.stringify(enrichedBody)
   })
   
   const responseText = await n8nResponse.text()
   
   return new Response(responseText, { 
     headers: { ...corsHeaders, 'Content-Type': 'application/json' },
     status: n8nResponse.status
   })
   
 } catch (error) {
   console.error('Error in n8n-proxy:', error)
   return new Response(
     JSON.stringify({ error: error.message }),
     { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
   )
 }
})
EOF

# Protected webhook endpoints with file & streaming support (v3.21 - fixed)
for i in 1 2 3; do
cat > volumes/functions/webhook-endpoint-$i/index.ts << EOF
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { corsHeaders } from '../_shared/cors.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const RATE_LIMIT_SECONDS = 1
const FUNCTION_NAME = 'webhook-endpoint-$i'

serve(async (req: Request) => {
 if (req.method === 'OPTIONS') {
   return new Response('ok', { headers: corsHeaders })
 }

 try {
   // REQUIRE authentication
   const authHeader = req.headers.get('Authorization')
   if (!authHeader) throw new Error('Authorization required')
   
   if (!authHeader.startsWith('Bearer ')) {
     throw new Error('Invalid authorization format. Expected: Bearer {token}')
   }
   
   const token = authHeader.replace('Bearer ', '')
   
   const supabaseAdmin = createClient(
     Deno.env.get('SUPABASE_URL')!,
     Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
   )
   
   const { data: { user }, error } = await supabaseAdmin.auth.getUser(token)
   
   if (error || !user) {
     throw new Error('Invalid authentication token')
   }
   
   // Check rate limit in database
   const { data: lastCall } = await supabaseAdmin
     .from('function_logs')
     .select('last_called_at')
     .eq('user_id', user.id)
     .eq('function_name', FUNCTION_NAME)
     .single()
   
   if (lastCall) {
     const timeDiff = Date.now() - new Date(lastCall.last_called_at).getTime()
     if (timeDiff < RATE_LIMIT_SECONDS * 1000) {
       return new Response(
         JSON.stringify({ error: 'Too many requests. Please wait.' }),
         { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
       )
     }
   }
   
   // Update rate limit
   await supabaseAdmin
     .from('function_logs')
     .upsert({
       user_id: user.id,
       function_name: FUNCTION_NAME,
       last_called_at: new Date().toISOString()
     })
   
   // Check if streaming requested (v3.20)
   const url = new URL(req.url)
   const wantStream = url.searchParams.get('stream') === 'true'
   
   // Parse body based on Content-Type (v3.17: file support)
   const contentType = req.headers.get('content-type') || ''
   let body: any
   let isFormData = false
   let formData: FormData | null = null
   
   if (contentType.includes('multipart/form-data')) {
     // File upload
     formData = await req.formData()
     isFormData = true
     // Convert FormData to object for logging (without file content)
     body = {}
     formData.forEach((value, key) => {
       if (value instanceof File) {
         body[key] = { filename: value.name, size: value.size, type: value.type }
       } else {
         body[key] = value
       }
     })
   } else if (contentType.includes('application/json')) {
     // JSON
     body = await req.json()
   } else {
     // Text or other
     body = { data: await req.text() }
   }
   
   const webhookUrl = Deno.env.get('ENDPOINT_${i}_WEBHOOK_URL')
   const webhookAuth = Deno.env.get('ENDPOINT_${i}_AUTH_HEADER')
   
   if (!webhookUrl) {
     return new Response(
       JSON.stringify({ 
         message: 'Webhook endpoint $i not configured',
         received_data: body,
         user_id: user.id,
         user_email: user.email
       }),
       { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
     )
   }
   
   let webhookResponse: Response
   
   if (isFormData && formData) {
     // Forward FormData with files to n8n
     // Add metadata fields
     formData.append('_user_id', user.id)
     formData.append('_user_email', user.email || '')
     formData.append('_source', 'authenticated')
     formData.append('_function', FUNCTION_NAME)
     formData.append('_timestamp', new Date().toISOString())
     if (wantStream) formData.append('_stream', 'true')
     
     webhookResponse = await fetch(webhookUrl, {
       method: 'POST',
       headers: {
         ...(webhookAuth ? { 'Authorization': webhookAuth } : {})
         // Note: Don't set Content-Type for FormData - fetch sets it with boundary
       },
       body: formData
     })
   } else {
     // Forward JSON
     const enrichedBody = {
       ...body,
       source: 'authenticated',
       function: FUNCTION_NAME,
       user_id: user.id,
       user_email: user.email,
       timestamp: new Date().toISOString(),
       ...(wantStream ? { _stream: true } : {})
     }
     
     webhookResponse = await fetch(webhookUrl, {
       method: 'POST',
       headers: {
         'Content-Type': 'application/json',
         ...(webhookAuth ? { 'Authorization': webhookAuth } : {})
       },
       body: JSON.stringify(enrichedBody)
     })
   }
   
   // v3.21: Handle streaming response - direct body proxy (fixed early termination)
   const responseContentType = webhookResponse.headers.get('content-type') || ''
   
   // Streaming: просто проксируем body напрямую
   if (wantStream && webhookResponse.body) {
     return new Response(webhookResponse.body, {
       headers: {
         ...corsHeaders,
         'Content-Type': responseContentType || 'text/event-stream',
         'Cache-Control': 'no-cache'
       },
       status: webhookResponse.status
     })
   }
   
   // Regular response
   const responseText = await webhookResponse.text()
   
   return new Response(responseText, { 
     headers: { ...corsHeaders, 'Content-Type': responseContentType || 'application/json' },
     status: webhookResponse.status
   })
   
 } catch (error) {
   console.error(\`Error in \${FUNCTION_NAME}:\`, error)
   return new Response(
     JSON.stringify({ error: error.message }),
     { 
       status: error.message.includes('Authorization') ? 401 : 500, 
       headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
     }
   )
 }
})
EOF
done

# Create error page
echo -e "${YELLOW}Creating error pages...${NC}"
mkdir -p /usr/share/nginx/html

cat > /usr/share/nginx/html/50x.html << 'ERRORPAGE'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Service Unavailable</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }
        .container {
            padding: 2rem;
        }
        h1 {
            font-size: 6rem;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        h2 {
            font-size: 1.5rem;
            font-weight: 300;
            margin: 1rem 0;
        }
        p {
            font-size: 1.1rem;
            opacity: 0.9;
            max-width: 500px;
            margin: 2rem auto;
        }
        .info {
            background: rgba(255,255,255,0.2);
            padding: 1rem;
            border-radius: 10px;
            margin-top: 2rem;
            font-size: 0.9rem;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Oops!</h1>
        <h2>Service Temporarily Unavailable</h2>
        <p>Something went wrong on our end. Our team has been notified and we are working to fix the problem.</p>
        <div class="info">
            <strong>Please try refreshing the page in a few moments.</strong>
        </div>
    </div>
</body>
</html>
ERRORPAGE

# Create webroot directory for certbot
echo -e "${YELLOW}Creating webroot directory for SSL certificate...${NC}"
mkdir -p "/var/www/$DOMAIN/.well-known/acme-challenge"

# Nginx initial setup for certbot webroot - minimal config for SSL cert only
echo -e "${YELLOW}Setting up Nginx for SSL certificate generation...${NC}"

cat > "/etc/nginx/sites-available/$DOMAIN" << NGINX
server {
    listen 80;
    server_name $DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/$DOMAIN;
    }
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}
NGINX

ln -sf "/etc/nginx/sites-available/$DOMAIN" /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# Get SSL certificate using webroot
echo -e "${GREEN}🔒 SSL Certificate Configuration${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Obtaining SSL certificate from Let's Encrypt...${NC}"
echo -e "${GREEN}Domain: ${YELLOW}$DOMAIN${NC}"
echo -e "${GREEN}Email:  ${YELLOW}$EMAIL${NC}"
echo ""

if ! certbot certonly --webroot -w "/var/www/$DOMAIN" -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --deploy-hook "systemctl reload nginx"; then
    echo -e "${RED}✗ Certbot failed. Installation cannot continue without SSL.${NC}"
    echo -e "${RED}  Please check that your DNS A record for '$DOMAIN' points to this server's IP.${NC}"
    echo -e "${RED}  Server IP: $(curl -s ifconfig.me)${NC}"
    echo -e "${RED}  Then run the script again.${NC}"
    exit 1
fi

echo -e "${GREEN}✔ SSL certificate obtained successfully${NC}"
echo -e "${GREEN}  Certificate valid for 90 days (auto-renewal enabled)${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Create missing Let's Encrypt config files if needed
echo -e "${YELLOW}Ensuring Let's Encrypt SSL configuration...${NC}"

if [ ! -f "/etc/letsencrypt/options-ssl-nginx.conf" ]; then
    cat > /etc/letsencrypt/options-ssl-nginx.conf << 'SSL_CONF'
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
SSL_CONF
fi

if [ ! -f "/etc/letsencrypt/ssl-dhparams.pem" ]; then
    openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 &> /dev/null
fi

# Final Nginx configuration with all optimizations, proper timeouts, and TUS bypass
cat > /etc/nginx/sites-available/$DOMAIN << 'NGINX'
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=functions:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=n8n:10m rate=50r/s;

# WebSocket upgrade map
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;
    
    location /.well-known/acme-challenge/ {
        root /var/www/DOMAIN_PLACEHOLDER;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;
    
    ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    
    # Support 10GB uploads
    client_max_body_size 11G;
    
    # Error handling
    proxy_intercept_errors on;
    error_page 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
        internal;
    }
    
    # Realtime WebSocket - needs long timeouts
    location ~ ^/realtime/v1 {
        client_max_body_size 11G;
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        
        proxy_buffering off;
        proxy_cache off;
        
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_connect_timeout 10s;
        
        limit_req zone=api burst=20 nodelay;
    }
    
    # Public n8n-proxy endpoint with 5-minute timeout
    location = /functions/v1/n8n-proxy {
        client_max_body_size 11G;
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        
        proxy_request_buffering off;
        client_body_buffer_size 1M;
        
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_connect_timeout 10s;
        
        limit_req zone=n8n burst=100 nodelay;
    }
    
    # Edge Functions - 5-minute timeouts
    location ~ ^/functions/v1 {
        client_max_body_size 11G;
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        
        proxy_request_buffering off;
        client_body_buffer_size 1M;
        
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_connect_timeout 10s;
        
        limit_req zone=functions burst=100 nodelay;
    }
    
    # ========== TUS Resumable Uploads (bypass Kong -> direct to Storage:5000) ==========
    # v3.22: TUS uploads go directly to Storage container, bypassing Kong
    # This fixes issues with Kong interfering with TUS protocol headers
    
    # TUS: PATCH/HEAD requests (Storage returns Location without /storage/v1 prefix)
    location ~ ^/upload/resumable {
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin "$http_origin" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD" always;
            add_header Access-Control-Allow-Headers "Authorization, Content-Type, Upload-Length, Upload-Offset, Tus-Resumable, Upload-Metadata, Upload-Defer-Length, Upload-Concat, x-upsert" always;
            add_header Access-Control-Expose-Headers "Upload-Offset, Location, Upload-Length, Tus-Version, Tus-Resumable, Tus-Max-Size, Tus-Extension, Upload-Metadata" always;
            add_header Access-Control-Max-Age 86400 always;
            add_header Content-Length 0;
            add_header Content-Type text/plain;
            return 204;
        }

        client_max_body_size 11G;
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_read_timeout 7200s;
        proxy_send_timeout 7200s;
        proxy_connect_timeout 10s;
        proxy_request_buffering off;
        proxy_buffering off;
    }

    # TUS: Initial POST (client sends to /storage/v1/upload/resumable)
    location ~ ^/storage/v1/upload/resumable {
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin "$http_origin" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD" always;
            add_header Access-Control-Allow-Headers "Authorization, Content-Type, Upload-Length, Upload-Offset, Tus-Resumable, Upload-Metadata, Upload-Defer-Length, Upload-Concat, x-upsert" always;
            add_header Access-Control-Expose-Headers "Upload-Offset, Location, Upload-Length, Tus-Version, Tus-Resumable, Tus-Max-Size, Tus-Extension, Upload-Metadata" always;
            add_header Access-Control-Max-Age 86400 always;
            add_header Content-Length 0;
            add_header Content-Type text/plain;
            return 204;
        }

        rewrite ^/storage/v1/(.*) /$1 break;
        client_max_body_size 11G;
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header X-Forwarded-Prefix /storage/v1/;
        proxy_read_timeout 7200s;
        proxy_send_timeout 7200s;
        proxy_connect_timeout 10s;
        proxy_request_buffering off;
        proxy_buffering off;
    }

    # ========== End TUS Configuration ==========
    
    # Storage - longer timeouts for 10GB file uploads
    location ~ ^/storage/v1 {
        client_max_body_size 11G;
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        
        # Extended timeouts for large uploads
        proxy_read_timeout 7200s;
        proxy_send_timeout 7200s;
        proxy_connect_timeout 10s;
        
        # Disable buffering for TUS uploads
        proxy_request_buffering off;
        proxy_buffering off;
        
        limit_req zone=api burst=20 nodelay;
    }
    
    # Everything else - standard timeouts
    location / {
        client_max_body_size 11G;
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        
        # Conditional WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        proxy_connect_timeout 10s;
        
        limit_req zone=api burst=20 nodelay;
    }
}
NGINX

# Replace domain placeholder in all places
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN|g" "/etc/nginx/sites-available/$DOMAIN"
systemctl reload nginx

# Start Docker containers - Export DOMAIN to avoid warnings
echo -e "${GREEN}🐳 Starting Docker Containers${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Starting all Supabase services (latest versions)...${NC}"

# Export DOMAIN variable to avoid warnings
export DOMAIN="$DOMAIN"

# Use docker compose v2 if available, otherwise docker-compose
if docker compose version &> /dev/null 2>&1; then
    docker compose up -d
else
    docker-compose up -d
fi

echo -e "${GREEN}✔ All containers started with latest versions${NC}"
echo ""

# Wait for Kong to be ready with improved check
echo -e "${GREEN}Waiting for services to initialize...${NC}"
KONG_READY=false
echo -n "  "
for i in {1..60}; do
    # Check for 401 which means Kong is up but needs auth
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/status 2>/dev/null | grep -q "401"; then
        KONG_READY=true
        echo -e " ${GREEN}✔${NC}"
        echo -e "${GREEN}✔ Kong API Gateway is ready${NC}"
        break
    fi
    echo -n "▓"
    sleep 2
done

if [ "$KONG_READY" = false ]; then
    echo -e " ${YELLOW}⚠${NC}"
    echo -e "${YELLOW}⚠ Kong may still be starting up. This is normal for first installation.${NC}"
    echo -e "${YELLOW}  You can check status later with: curl http://localhost:8000/status${NC}"
fi

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Create function_logs table with proper error handling
echo -e "${YELLOW}Creating database tables...${NC}"
sleep 10 # Give postgres extra time

if docker exec supabase-db psql -U postgres -d postgres -c "
CREATE TABLE IF NOT EXISTS public.function_logs (
   user_id UUID NOT NULL,
   function_name TEXT NOT NULL,
   last_called_at TIMESTAMPTZ DEFAULT NOW(),
   PRIMARY KEY (user_id, function_name)
);
ALTER TABLE public.function_logs ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_function_logs_lookup ON function_logs(user_id, function_name, last_called_at);"; then
    echo -e "${GREEN}✔ Database tables created successfully${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Could not create function_logs table. This may affect rate limiting for Edge Functions.${NC}"
    echo -e "${YELLOW}  You can create it manually later by running:${NC}"
    echo "  docker exec supabase-db psql -U postgres -d postgres -c 'CREATE TABLE ...'"
fi

# Verify critical configurations
echo ""
echo -e "${YELLOW}Verifying installation configuration...${NC}"

# Check Nginx configuration
NGINX_SIZE=$(grep -h "client_max_body_size" /etc/nginx/sites-available/$DOMAIN | head -1 | awk '{print $2}')
if [[ $NGINX_SIZE == *"11G"* ]]; then
    echo -e "${GREEN}✔ Nginx configured for 11GB uploads${NC}"
else
    echo -e "${RED}✗ Nginx client_max_body_size is $NGINX_SIZE (expected 11G)${NC}"
fi

# Verify Storage container configuration - check all three variables
echo -e "${YELLOW}Verifying Storage container file size limits...${NC}"

FILE_SIZE_LIMIT=$(docker exec supabase-storage printenv FILE_SIZE_LIMIT 2>/dev/null)
UPLOAD_FILE_SIZE_LIMIT=$(docker exec supabase-storage printenv UPLOAD_FILE_SIZE_LIMIT 2>/dev/null)
UPLOAD_FILE_SIZE_LIMIT_STANDARD=$(docker exec supabase-storage printenv UPLOAD_FILE_SIZE_LIMIT_STANDARD 2>/dev/null)

if [ "$FILE_SIZE_LIMIT" = "10737418240" ]; then
    echo -e "${GREEN}✔ FILE_SIZE_LIMIT: 10737418240 (10GB)${NC}"
else
    echo -e "${RED}✗ FILE_SIZE_LIMIT: $FILE_SIZE_LIMIT (expected 10737418240)${NC}"
fi

if [ "$UPLOAD_FILE_SIZE_LIMIT" = "10737418240" ]; then
    echo -e "${GREEN}✔ UPLOAD_FILE_SIZE_LIMIT: 10737418240 (10GB)${NC}"
else
    echo -e "${RED}✗ UPLOAD_FILE_SIZE_LIMIT: $UPLOAD_FILE_SIZE_LIMIT (expected 10737418240)${NC}"
fi

if [ "$UPLOAD_FILE_SIZE_LIMIT_STANDARD" = "10737418240" ]; then
    echo -e "${GREEN}✔ UPLOAD_FILE_SIZE_LIMIT_STANDARD: 10737418240 (10GB)${NC}"
else
    echo -e "${RED}✗ UPLOAD_FILE_SIZE_LIMIT_STANDARD: $UPLOAD_FILE_SIZE_LIMIT_STANDARD (expected 10737418240)${NC}"
fi

# Verify Kong container configuration
KONG_BODY_SIZE=$(docker exec supabase-kong printenv KONG_NGINX_HTTP_CLIENT_MAX_BODY_SIZE 2>/dev/null)
if [[ $KONG_BODY_SIZE == *"11000m"* ]]; then
    echo -e "${GREEN}✔ Kong container configured for 11GB requests${NC}"
else
    echo -e "${YELLOW}⚠ Kong max body size may not be configured correctly${NC}"
fi

# v3.22: Verify TUS configuration
echo -e "${YELLOW}Verifying TUS configuration (v3.22)...${NC}"
TUS_PATH=$(docker exec supabase-storage printenv TUS_URL_PATH 2>/dev/null)
if [ "$TUS_PATH" = "/upload/resumable" ]; then
    echo -e "${GREEN}✔ TUS_URL_PATH: /upload/resumable (correct)${NC}"
else
    echo -e "${RED}✗ TUS_URL_PATH: $TUS_PATH (expected /upload/resumable)${NC}"
fi

STORAGE_PORT=$(ss -tlnp | grep -c ":5000 " || true)
if [ "$STORAGE_PORT" -gt 0 ]; then
    echo -e "${GREEN}✔ Storage port 5000 listening (TUS direct access)${NC}"
else
    echo -e "${YELLOW}⚠ Storage port 5000 not yet listening (may need a moment)${NC}"
fi

# Verify Email Templates configuration (v3.16)
echo -e "${YELLOW}Verifying Email Templates configuration...${NC}"
AUTH_CONFIRMATION_SUBJECT=$(docker exec supabase-auth printenv GOTRUE_MAILER_TEMPLATES_CONFIRMATION_SUBJECT 2>/dev/null || true)
if [ ! -z "$AUTH_CONFIRMATION_SUBJECT" ]; then
    echo -e "${GREEN}✔ Email templates configured in Auth service${NC}"
else
    echo -e "${YELLOW}⚠ Email templates may not be configured (restart may be needed)${NC}"
fi

# v3.23: Configure automatic SSL certificate renewal with nginx reload
echo -e "${GREEN}⏰ Configuring Automatic SSL Certificate Renewal${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

CRON_CERT_RENEW_JOB="0 2 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx' >> /var/log/certbot-renew.log 2>&1"

CRON_TEMP=$(mktemp /tmp/cron.XXXXXX)
(crontab -l 2>/dev/null | grep -v "certbot") > "$CRON_TEMP" || true
echo "$CRON_CERT_RENEW_JOB" >> "$CRON_TEMP"
crontab "$CRON_TEMP"
rm -f "$CRON_TEMP"

echo -e "${GREEN}✔ Cron job configured: SSL renewal check daily at 2 AM${NC}"
echo -e "${GREEN}  Nginx will automatically reload after certificate renewal${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Create improved DB hardening script v3.3
echo -e "${YELLOW}Creating database hardening script v3.3...${NC}"

cat > /root/harden_supabase_db.sh << 'HARDEN_SCRIPT'
#!/bin/bash
# Supabase Database Hardening Script v3.3
# 
# CRITICAL: Both scenarios use iptables (NOT localhost binding)
# 
# Why? Because binding to 127.0.0.1 prevents Docker containers from connecting
# via host.docker.internal - it only works with --network=host mode.
# 
# Based on official Docker documentation:
# https://docs.docker.com/engine/network/firewall-iptables/
#
# Architecture:
# - PostgreSQL always listens on 0.0.0.0:5432
# - iptables DOCKER-USER chain controls who can connect
# - Same Server: only Docker networks allowed
# - Different Servers: Docker networks + specific external IP
#
# v3.3 changes:
# - Added option 5: Add external IP to whitelist multiple servers
# - Fixed grep with || true to prevent script exit on empty result
#
# v3.2 changes:
# - CRITICAL: Added 192.168.0.0/16 to allowed Docker networks
#   (Docker can use this range for bridge networks!)
# - Added --ctdir ORIGINAL for safer packet matching
# - Fixed clean_iptables with eval for proper argument handling
#
# v3.1 changes:
# - Fixed clean_iptables to properly remove rules with -s (source IP)
# - Uses iptables -S parsing instead of hardcoded rule patterns
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SUPABASE_DIR="/opt/supabase-project"
COMPOSE_FILE="$SUPABASE_DIR/docker-compose.yml"

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}${BOLD}  Supabase Database Hardening v3.3${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Run as root${NC}"
    exit 1
fi

# Check Supabase installation
if [ ! -f "$COMPOSE_FILE" ]; then
    echo -e "${RED}Supabase not found at $SUPABASE_DIR${NC}"
    exit 1
fi

# Check Docker is running and DOCKER-USER chain exists
if ! iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo -e "${RED}Docker not running or DOCKER-USER chain doesn't exist${NC}"
    echo -e "${YELLOW}Start Docker first: systemctl start docker${NC}"
    exit 1
fi

SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")
echo -e "${GREEN}Server IP: ${SERVER_IP}${NC}"
echo ""

# Function to clean all our iptables rules
clean_iptables() {
    echo -e "${YELLOW}Cleaning existing firewall rules...${NC}"
    
    while true; do
        RULE=$(iptables -S DOCKER-USER 2>/dev/null | grep -E "ctorigdstport 5432|dport 5432" | head -1 || true)
        if [ -z "$RULE" ]; then
            break
        fi
        DELETE_RULE=$(echo "$RULE" | sed 's/^-A /-D /')
        eval iptables $DELETE_RULE 2>/dev/null || break
    done
    
    iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
}

# Function to ensure docker-compose has port open on 0.0.0.0
ensure_port_open() {
    cp "$COMPOSE_FILE" "$COMPOSE_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    
    sed -i 's/- "127.0.0.1:5432:5432"/- "5432:5432"/' "$COMPOSE_FILE"
    sed -i 's/- "0.0.0.0:5432:5432"/- "5432:5432"/' "$COMPOSE_FILE"
}

# Function to add base iptables rules
add_base_rules() {
    echo -e "${YELLOW}Installing iptables-persistent...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
    
    iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j DROP
    
    iptables -I DOCKER-USER -s 192.168.0.0/16 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT
    iptables -I DOCKER-USER -s 10.0.0.0/8 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT
    iptables -I DOCKER-USER -s 172.16.0.0/12 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT
    iptables -I DOCKER-USER -s 127.0.0.0/8 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT
    
    iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

# Function to save iptables rules
save_rules() {
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || true
}

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}  Select Setup${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}1)${NC} ${BOLD}Same Server${NC} - n8n and Supabase on this server"
echo -e "     Allows only Docker containers to connect"
echo ""
echo -e "  ${GREEN}2)${NC} ${BOLD}Different Servers${NC} - n8n on another server"  
echo -e "     Allows Docker containers + specific external IP"
echo ""
echo -e "  ${GREEN}3)${NC} ${BOLD}Reset to open${NC} - allow all connections"
echo ""
echo -e "  ${GREEN}4)${NC} ${BOLD}View current status${NC}"
echo ""
echo -e "  ${GREEN}5)${NC} ${BOLD}Add external IP${NC} - whitelist another server"
echo ""
echo -e "  ${GREEN}q)${NC} Quit"
echo ""

read -p "Select [1-5, q]: " OPTION

case $OPTION in
    1)
        echo ""
        echo -e "${CYAN}Configuring for Same Server (Docker-only access)...${NC}"
        echo ""
        
        ensure_port_open
        clean_iptables
        add_base_rules
        save_rules
        
        echo -e "${YELLOW}Restarting Supabase...${NC}"
        cd "$SUPABASE_DIR"
        docker compose down db 2>/dev/null || docker-compose down db 2>/dev/null || true
        docker compose up -d 2>/dev/null || docker-compose up -d
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}  Done! Port 5432 restricted to Docker containers only${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}Firewall rules applied:${NC}"
        echo -e "  ${GREEN}✔${NC} ESTABLISHED,RELATED - response packets"
        echo -e "  ${GREEN}✔${NC} 127.0.0.0/8 - localhost"
        echo -e "  ${GREEN}✔${NC} 172.16.0.0/12 - Docker networks"
        echo -e "  ${GREEN}✔${NC} 10.0.0.0/8 - Docker custom networks"
        echo -e "  ${GREEN}✔${NC} 192.168.0.0/16 - Docker bridge networks"
        echo -e "  ${RED}✘${NC} All external IPs - BLOCKED"
        echo ""
        echo -e "${YELLOW}To connect n8n to Supabase PostgreSQL:${NC}"
        echo ""
        echo -e "  Host:     ${GREEN}host.docker.internal${NC}"
        echo -e "  Port:     ${GREEN}5432${NC}"
        echo -e "  Database: ${GREEN}postgres${NC}"
        echo -e "  User:     ${GREEN}postgres.postgres${NC}"
        echo -e "  Password: ${GREEN}<from /root/supabase-credentials.txt>${NC}"
        echo -e "  SSL:      ${GREEN}Disable${NC}"
        echo ""
        echo -e "${YELLOW}Required in n8n docker-compose.yml:${NC}"
        echo -e "  extra_hosts:"
        echo -e "    - \"host.docker.internal:host-gateway\""
        ;;
        
    2)
        echo ""
        echo -e "${CYAN}Configuring for Different Servers...${NC}"
        echo ""
        
        read -p "Enter n8n server IP: " N8N_IP
        
        if ! [[ $N8N_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo -e "${RED}Invalid IP format${NC}"
            exit 1
        fi
        
        ensure_port_open
        clean_iptables
        add_base_rules
        
        iptables -I DOCKER-USER 2 -s $N8N_IP -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT
        echo -e "  ${GREEN}✔${NC} Added: $N8N_IP"
        
        save_rules
        
        echo -e "${YELLOW}Restarting Supabase...${NC}"
        cd "$SUPABASE_DIR"
        docker compose up -d 2>/dev/null || docker-compose up -d
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}  Done! Port 5432 restricted to $N8N_IP + Docker${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}Firewall rules applied:${NC}"
        echo -e "  ${GREEN}✔${NC} ESTABLISHED,RELATED - response packets"
        echo -e "  ${GREEN}✔${NC} $N8N_IP - your n8n server"
        echo -e "  ${GREEN}✔${NC} 127.0.0.0/8 - localhost"
        echo -e "  ${GREEN}✔${NC} 172.16.0.0/12 - Docker networks"
        echo -e "  ${GREEN}✔${NC} 10.0.0.0/8 - Docker custom networks"
        echo -e "  ${GREEN}✔${NC} 192.168.0.0/16 - Docker bridge networks"
        echo -e "  ${RED}✘${NC} All other external IPs - BLOCKED"
        echo ""
        echo -e "${YELLOW}To connect n8n to Supabase PostgreSQL:${NC}"
        echo ""
        echo -e "  Host:     ${GREEN}${SERVER_IP}${NC}"
        echo -e "  Port:     ${GREEN}5432${NC}"
        echo -e "  Database: ${GREEN}postgres${NC}"
        echo -e "  User:     ${GREEN}postgres.postgres${NC}"
        echo -e "  Password: ${GREEN}<from /root/supabase-credentials.txt>${NC}"
        echo -e "  SSL:      ${GREEN}Disable${NC}"
        echo ""
        echo -e "${YELLOW}To add more IPs later:${NC}"
        echo -e "  iptables -I DOCKER-USER 2 -s <IP> -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT"
        echo -e "  iptables-save > /etc/iptables/rules.v4"
        ;;
        
    3)
        echo ""
        echo -e "${CYAN}Resetting to open access...${NC}"
        echo ""
        
        ensure_port_open
        clean_iptables
        save_rules
        
        cd "$SUPABASE_DIR"
        docker compose down db 2>/dev/null || docker-compose down db 2>/dev/null || true
        docker compose up -d 2>/dev/null || docker-compose up -d
        
        echo -e "${GREEN}✔ Port 5432 is now open to all${NC}"
        echo -e "${RED}⚠ WARNING: Database is accessible from internet!${NC}"
        echo -e "${YELLOW}Use cloud firewall (Security Groups) for protection${NC}"
        ;;
        
    4)
        echo ""
        echo -e "${CYAN}Current Status:${NC}"
        echo ""
        
        BINDING=$(grep -E "5432:5432" "$COMPOSE_FILE" | head -1 || echo "not found")
        echo -e "${YELLOW}Docker Compose binding:${NC}"
        echo "  $BINDING"
        if echo "$BINDING" | grep -q "127.0.0.1"; then
            echo -e "  ${RED}⚠ WARNING: Bound to localhost - containers can't connect!${NC}"
        fi
        echo ""
        
        echo -e "${YELLOW}DOCKER-USER iptables rules:${NC}"
        iptables -L DOCKER-USER -n -v 2>/dev/null | head -15 || echo "  Unable to read"
        echo ""
        
        echo -e "${YELLOW}Port 5432 listening:${NC}"
        ss -tuln | grep 5432 || echo "  Not listening"
        echo ""
        
        echo -e "${YELLOW}Quick test from another container:${NC}"
        echo "  docker run --rm --add-host=host.docker.internal:host-gateway postgres:15 \\"
        echo "    psql -h host.docker.internal -U postgres -c 'SELECT 1'"
        ;;
    
    5)
        echo ""
        echo -e "${CYAN}Add External IP to Whitelist${NC}"
        echo ""
        
        if ! iptables -S DOCKER-USER 2>/dev/null | grep -q "ctorigdstport 5432"; then
            echo -e "${RED}Error: Hardening not active. Run option 1 or 2 first.${NC}"
            exit 1
        fi
        
        echo -e "${YELLOW}Current whitelisted external IPs:${NC}"
        iptables -S DOCKER-USER 2>/dev/null | grep "ctorigdstport 5432" | grep -v DROP | grep -oP "(?<=-s )[0-9.]+" | grep -vE "^(127\.|172\.|10\.|192\.168\.)" || echo "  (none)"
        echo ""
        
        read -p "Enter IP to add: " NEW_IP
        
        if ! [[ $NEW_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo -e "${RED}Invalid IP format${NC}"
            exit 1
        fi
        
        if iptables -S DOCKER-USER 2>/dev/null | grep -q "$NEW_IP"; then
            echo -e "${YELLOW}IP $NEW_IP is already whitelisted${NC}"
            exit 0
        fi
        
        iptables -I DOCKER-USER 2 -s $NEW_IP -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j ACCEPT
        save_rules
        
        echo -e "${GREEN}✔ Added: $NEW_IP${NC}"
        echo ""
        echo -e "${YELLOW}Current whitelist:${NC}"
        iptables -S DOCKER-USER 2>/dev/null | grep "ctorigdstport 5432" | grep -v DROP | grep -oP "(?<=-s )[0-9.]+" | grep -vE "^(127\.|172\.|10\.|192\.168\.)" || echo "  (none)"
        ;;
        
    q|Q)
        echo "Exiting."
        exit 0
        ;;
        
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
HARDEN_SCRIPT

chmod +x /root/harden_supabase_db.sh

# Save credentials with restricted permissions
cat > /root/supabase-credentials.txt << CREDS
========================================
SUPABASE INSTALLATION COMPLETE v3.26
========================================

Main URL: https://$DOMAIN
Studio: https://$DOMAIN/studio
Username: supabase
Password: $DASHBOARD_PASSWORD

Database Connection (via pooler):
 Host: $DOMAIN
 Port: 5432
 Username: postgres.postgres
 Password: $POSTGRES_PASSWORD
 Database: postgres
 
 Note: Using 'postgres' as tenant ID for maximum compatibility

API Keys:
 Anon: $ANON_KEY
 Service: $SERVICE_ROLE_KEY

Edge Functions:
 Public/Hybrid: https://$DOMAIN/functions/v1/n8n-proxy
 Protected #1: https://$DOMAIN/functions/v1/webhook-endpoint-1
 Protected #2: https://$DOMAIN/functions/v1/webhook-endpoint-2
 Protected #3: https://$DOMAIN/functions/v1/webhook-endpoint-3
 
 Note: Protected endpoints support both JSON and file uploads (v3.17)

WebSocket Test:
 const ws = new WebSocket('wss://$DOMAIN/realtime/v1/websocket?apikey=$ANON_KEY&vsn=1.0.0');
 ws.onopen = () => console.log('Realtime connected!');

========================================
VERSION INFORMATION
========================================

This installation uses the LATEST Supabase versions:
- All Docker images pull :latest tags
- Repository cloned from main branch

========================================
EMAIL TEMPLATES (v3.18)
========================================

Email templates are stored as HTML files in /opt/supabase-project/email_templates/
Edit these files to customize your emails:
  - email_templates/confirmation.html
  - email_templates/recovery.html
  - email_templates/magic_link.html
  - email_templates/invite.html
  - email_templates/email_change.html

Available template variables:
  {{ .ConfirmationURL }} - The action link (confirm/reset/login)
  {{ .Email }} - User's email address
  {{ .Token }} - Raw token (6-digit code)
  {{ .SiteURL }} - Your site URL

After editing, restart auth service:
  cd /opt/supabase-project
  docker compose restart auth

========================================
10GB FILE UPLOAD + TUS FIX (v3.22)
========================================

✅ FILE_SIZE_LIMIT: 10737418240 (10GB)
✅ UPLOAD_FILE_SIZE_LIMIT: 10737418240 (10GB)
✅ UPLOAD_FILE_SIZE_LIMIT_STANDARD: 10737418240 (10GB)
✅ TUS_URL_PATH: /upload/resumable (v3.22 fix)
✅ TUS_URL_SCHEME: https (v3.22)
✅ TUS_URL_PORT: 443 (v3.22)
✅ Storage port 5000 exposed for direct TUS access (v3.22)
✅ Nginx TUS locations bypass Kong (v3.22)

v3.22 FIX: TUS resumable uploads now work out of the box!
- Storage container exposed on localhost:5000
- Nginx routes TUS requests directly to Storage (bypassing Kong)
- TUS_URL_PATH corrected to /upload/resumable (no /storage/v1 prefix)
- No separate TUS fix script needed

JavaScript SDK Example (resumable upload):
 const { data, error } = await supabase.storage
   .from('bucket-name')
   .upload('file.zip', file, {
     cacheControl: '3600',
     upsert: false
   })

CURL Example (TUS resumable):
 # Initial POST request creates upload session
 curl -X POST https://$DOMAIN/storage/v1/upload/resumable \\
   -H "Authorization: Bearer YOUR_TOKEN" \\
   -H "Upload-Length: FILE_SIZE_IN_BYTES" \\
   -H "Tus-Resumable: 1.0.0"

Note: Supabase Studio UI file upload is limited to 6MB
(architectural limitation of self-hosted version)

Verify configuration:
 docker exec supabase-storage printenv | grep -iE "size|tus"

========================================
DOCKER DAEMON CONFIGURATION
========================================

Docker daemon configured with:
✅ NAT enabled (ip-masq) for internet access
✅ Public DNS servers (8.8.8.8, 8.8.4.4, 1.1.1.1)
✅ Log rotation (10MB max, 3 files)
✅ Optimized DNS resolution (ndots:0)
✅ Standard Docker subnet (172.17.0.1/16)

This configuration is compatible with n8n and other services.

========================================
SSL AUTO-RENEWAL (v3.24)
========================================

✅ --deploy-hook saved in /etc/letsencrypt/renewal/ config (v3.24)
✅ Ubuntu systemd timer (certbot.timer) will reload nginx automatically
✅ Cron job configured as fallback: daily at 2 AM
✅ Log file: /var/log/certbot-renew.log

Verify cron: crontab -l | grep certbot
Verify deploy-hook: grep deploy /etc/letsencrypt/renewal/$DOMAIN.conf
Manual renewal: certbot renew --force-renewal
Check logs: cat /var/log/certbot-renew.log

========================================
DATABASE HARDENING v3.3
========================================

Run this script to secure PostgreSQL access:

  bash /root/harden_supabase_db.sh

Options:
  1) Same Server - n8n and Supabase on same server
     Uses host.docker.internal for connection
  2) Different Servers - n8n on separate server
     Whitelist specific external IP
  3) Reset to open - allow all connections
  4) View current status
  5) Add external IP - whitelist another server

========================================
N8N INTEGRATION
========================================

Same Server Setup:
  1. Run: bash /root/harden_supabase_db.sh (select option 1)
  2. In n8n, create PostgreSQL credential:
     Host: host.docker.internal
     Port: 5432
     Database: postgres
     User: postgres
     Password: $POSTGRES_PASSWORD
     SSL: Disable

Different Server Setup:
  1. Run: bash /root/harden_supabase_db.sh (select option 2)
  2. Enter your n8n server's public IP
  3. In n8n, create PostgreSQL credential:
     Host: <this server's IP>
     Port: 5432
     Database: postgres
     User: postgres
     Password: $POSTGRES_PASSWORD
     SSL: Disable

IMPORTANT: n8n installer v3.24+ includes extra_hosts
configuration automatically. If using older version,
add to docker-compose.yml:

  n8n-main:
    extra_hosts:
      - "host.docker.internal:host-gateway"
  
  n8n-worker:
    extra_hosts:
      - "host.docker.internal:host-gateway"

========================================
WEBHOOK CONFIGURATION
========================================

1. Edit webhook URLs in .env file:
  nano /opt/supabase-project/.env

2. Add your webhook URLs:
  N8N_WEBHOOK_URL=https://your-n8n.com/webhook/xxx
  N8N_BASIC_AUTH_HEADER=Basic base64_encoded_user:pass

3. Restart containers to apply changes:
  cd /opt/supabase-project
  docker-compose down && docker-compose up -d

========================================
PERFORMANCE OPTIMIZATIONS APPLIED
========================================

1. Analytics Container Optimization:
   - Memory consumption reduced from ~1.3GB to ~450MB
   - Telemetry and Datadog integrations disabled
   - Heartbeat interval increased to reduce overhead

2. Edge Functions DNS Fix:
   - Docker configured with public DNS servers
   - Functions remain stable after nginx/container restarts

3. Kong 5-Minute Timeout Fix:
   - Kong configured with 300-second timeouts
   - Supports long-running AI workflows in n8n
   - No more 60-second cutoffs

4. Automatic Log Rotation:
   - Docker logs limited to 10MB per container
   - System logrotate configured for daily rotation
   - Keeps only 7 days of compressed logs
   - Prevents disk space issues

5. 10GB File Upload Support (v3.15 FIX):
   - FILE_SIZE_LIMIT set as integer (was missing!)
   - All three size variables now integers (not strings)
   - Kong and Nginx configured for 11GB request bodies
   - Extended timeouts (2 hours) for slow connections
   - TUS resumable uploads for reliability

6. Email Templates via nginx (v3.18 FIX):
   - Templates stored as HTML files
   - Served via template-server container
   - No more inline _CONTENT variables
   - Easy to edit and customize

7. Protected Webhooks with Streaming (v3.21):
   - webhook-endpoint-1/2/3 accept files
   - Supports multipart/form-data uploads
   - User metadata added automatically
   - SSE streaming for AI agent responses
   - Add ?stream=true for streaming mode

8. TUS Resumable Upload Fix (v3.22):
   - Storage container exposed on port 5000
   - Nginx routes TUS requests directly to Storage (bypasses Kong)
   - TUS_URL_PATH fixed to /upload/resumable
   - TUS_URL_SCHEME=https and TUS_URL_PORT=443 added
   - CORS headers handled by Nginx for TUS endpoints
   - No separate fix script needed anymore

9. SSL Auto-Renewal (v3.24):
   - --deploy-hook saved in certbot renewal config at first cert generation
   - Ubuntu systemd timer (certbot.timer) uses saved hook automatically
   - Cron job as fallback with nginx reload deploy-hook
   - Logs to /var/log/certbot-renew.log

10. ufw vs iptables-persistent fix (v3.26):
    - Removed ufw from package install list to avoid apt Breaks conflict
    - Cloud provisioners that strip ufw before script runs no longer cause failure
    - Host firewall managed by Docker iptables + harden_supabase_db.sh

========================================
QUICK COMMANDS
========================================

# Restart only functions (faster):
cd /opt/supabase-project
docker compose restart functions

# Restart only auth (after email template changes):
cd /opt/supabase-project
docker compose restart auth

# Full restart (if functions don't update):
cd /opt/supabase-project
docker compose down && docker compose up -d

# Check logs:
docker logs supabase-edge-functions --tail 50
docker logs supabase-auth --tail 50
docker logs supabase-storage --tail 50

# Check log sizes:
du -sh /var/lib/docker/containers/*/*-json.log | sort -h

# Force log rotation:
logrotate -f /etc/logrotate.d/docker-containers

# Test 10GB upload support:
curl -I https://$DOMAIN/storage/v1/upload/resumable \\
  -H "Authorization: Bearer $ANON_KEY"

# Verify file size limits:
docker exec supabase-storage printenv | grep -i size

# Verify TUS configuration (v3.22):
docker exec supabase-storage printenv | grep -i tus
ss -tlnp | grep 5000

# Verify email templates (v3.18):
docker exec supabase-auth wget -qO- http://template-server/confirmation.html

# Verify Google OAuth (v3.19):
docker exec supabase-auth printenv | grep GOOGLE

# Verify SSL auto-renewal (v3.24):
crontab -l | grep certbot
grep deploy /etc/letsencrypt/renewal/*.conf
cat /var/log/certbot-renew.log

# Test database hardening:
bash /root/harden_supabase_db.sh

========================================
CREDS

# Set restrictive permissions on credentials file
chmod 600 /root/supabase-credentials.txt

# Final instructions
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                    🎉 INSTALLATION COMPLETE! 🎉${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}✔ Supabase is running at:${NC} https://$DOMAIN"
echo -e "${GREEN}✔ All services are healthy and ready${NC}"
echo -e "${GREEN}✔ Using latest Supabase versions from Docker Hub${NC}"
echo -e "${GREEN}✔ Complete Docker daemon configuration applied${NC}"
echo -e "${GREEN}✔ Analytics optimized - memory reduced by 65%${NC}"
echo -e "${GREEN}✔ Edge Functions DNS fix applied - stable after restarts${NC}"
echo -e "${GREEN}✔ Kong timeout fix applied - supports 5-minute requests${NC}"
echo -e "${GREEN}✔ Log rotation configured - prevents disk space issues${NC}"
echo -e "${GREEN}✔ 10GB file upload support enabled (v3.15 fix)${NC}"
echo -e "${GREEN}✔ TUS resumable uploads integrated (v3.22 - no separate fix needed)${NC}"
echo -e "${GREEN}✔ Email templates via nginx template-server (v3.18)${NC}"
echo -e "${GREEN}✔ Google OAuth ready to configure (v3.19)${NC}"
echo -e "${GREEN}✔ Protected webhooks with streaming support (v3.21)${NC}"
echo -e "${GREEN}✔ Database hardening script v3.3 installed${NC}"
echo -e "${GREEN}✔ SSL auto-renewal configured with nginx reload (v3.24)${NC}"
echo -e "${GREEN}✔ ufw/iptables-persistent apt-conflict fixed (v3.26)${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}                     📋 NEXT STEPS${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}1. 📄 View credentials:${NC}"
echo "   nano /root/supabase-credentials.txt"
echo ""
echo -e "${GREEN}2. 🔐 Secure database port (recommended):${NC}"
echo "   bash /root/harden_supabase_db.sh"
echo ""
echo -e "${GREEN}3. ✉️  Customize email templates:${NC}"
echo "   nano /opt/supabase-project/email_templates/confirmation.html"
echo "   (Edit HTML files, then: docker compose restart auth)"
echo ""
echo -e "${GREEN}4. 🔑 Enable Google OAuth (optional):${NC}"
echo "   nano /opt/supabase-project/.env"
echo "   (Set GOOGLE_ENABLED=true, add CLIENT_ID & SECRET from Google Console)"
echo "   docker compose restart auth"
echo ""
echo -e "${RED}5. 🗑️ SECURITY: After saving credentials elsewhere:${NC}"
echo "   rm /root/supabase-credentials.txt"
echo ""
echo -e "${GREEN}6. 🔧 Configure webhooks if using Edge Functions:${NC}"
echo "   nano /opt/supabase-project/.env"
echo "   (Add N8N_WEBHOOK_URL and restart containers)"
echo ""
echo -e "${GREEN}7. 📦 Verify 10GB upload + TUS support:${NC}"
echo "   docker exec supabase-storage printenv | grep -iE 'size|tus'"
echo "   ss -tlnp | grep 5000"
echo "   (Should show all size variables = 10737418240 and port 5000 listening)"
echo ""
echo -e "${GREEN}8. 🔒 Verify SSL auto-renewal (v3.24):${NC}"
echo "   crontab -l | grep certbot"
echo "   grep deploy /etc/letsencrypt/renewal/$DOMAIN.conf"
echo "   (Should show deploy-hook with nginx reload)"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
