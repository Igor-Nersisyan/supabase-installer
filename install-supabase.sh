#!/bin/bash
# Supabase Self-Hosted Production Installer v3.2 - Fixed
# With Docker detection and firewall configuration

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Supabase Self-Hosted Installer v3.2${NC}"
echo -e "${GREEN}      (Fixed for existing Docker)${NC}"
echo -e "${GREEN}========================================${NC}\n"

if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Run as root${NC}"
  exit 1
fi

# Input
read -p "Domain: " DOMAIN
read -p "Email for SSL: " EMAIL

# Generate passwords
echo -e "${YELLOW}Generating secure passwords...${NC}"
POSTGRES_PASSWORD=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
DASHBOARD_PASSWORD=$(openssl rand -hex 16)
SECRET_KEY_BASE=$(openssl rand -hex 32)
VAULT_ENC_KEY=$(openssl rand -hex 16)

# Wait for apt locks to be released
echo -e "${YELLOW}Checking for apt locks...${NC}"
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
   echo -e "${YELLOW}Waiting for other package managers to finish...${NC}"
   sleep 5
done

# Install packages with smart Docker detection
echo -e "${YELLOW}Checking installed packages...${NC}"
apt-get update -qq

# Check if Docker is already installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Installing Docker...${NC}"
    apt-get install -y docker.io -qq
else
    echo -e "${GREEN}✓ Docker already installed ($(docker --version))${NC}"
fi

# Check if docker-compose is already installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}Installing Docker Compose...${NC}"
    apt-get install -y docker-compose -qq
else
    echo -e "${GREEN}✓ Docker Compose already installed${NC}"
fi

# Install other required packages
echo -e "${YELLOW}Installing other required packages...${NC}"
PACKAGES_TO_INSTALL=""

# Check each package and add to install list if not present
for pkg in git nginx certbot python3-certbot-nginx wget curl nano ufw python3-yaml; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
    else
        echo -e "${GREEN}✓ $pkg already installed${NC}"
    fi
done

if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
    echo -e "${YELLOW}Installing:$PACKAGES_TO_INSTALL${NC}"
    apt-get install -y $PACKAGES_TO_INSTALL -qq
fi

# Install docker compose v2 if needed
if ! docker compose version &> /dev/null 2>&1; then
   echo -e "${YELLOW}Installing Docker Compose v2 plugin...${NC}"
   mkdir -p /usr/local/lib/docker/cli-plugins/
   curl -SL https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
   chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
   echo -e "${GREEN}✓ Docker Compose v2 plugin installed${NC}"
else
   echo -e "${GREEN}✓ Docker Compose v2 already available${NC}"
fi

# Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
if command -v ufw &> /dev/null; then
   echo -e "${YELLOW}Adding firewall rules...${NC}"
   ufw allow 22/tcp comment 'SSH' 2>/dev/null
   ufw allow 80/tcp comment 'HTTP for SSL cert' 2>/dev/null  
   ufw allow 443/tcp comment 'HTTPS' 2>/dev/null
   ufw allow 5432/tcp comment 'PostgreSQL' 2>/dev/null
   
   UFW_STATUS=$(ufw status | grep -c "Status: active" || true)
   if [ "$UFW_STATUS" -eq 0 ]; then
       echo -e "${YELLOW}Enabling firewall...${NC}"
       ufw --force enable
       echo -e "${GREEN}Firewall enabled with ports: 22, 80, 443, 5432${NC}"
   else
       echo -e "${GREEN}Firewall already active. Rules added: 22, 80, 443, 5432${NC}"
   fi
else
   echo -e "${YELLOW}UFW not installed, skipping firewall configuration${NC}"
fi

# Clone Supabase
echo -e "${YELLOW}Setting up Supabase directory...${NC}"
cd /opt
rm -rf supabase-project
git clone --depth 1 https://github.com/supabase/supabase.git
mkdir -p supabase-project
cp -r supabase/docker/* supabase-project/
cp supabase/docker/.env.example supabase-project/.env
cd supabase-project

# Fix docker-compose.yml for compatibility
sed -i '/^name:/d' docker-compose.yml 2>/dev/null || true
sed -i 's/: true/: "true"/g' docker-compose.yml
sed -i 's/: false/: "false"/g' docker-compose.yml

# Install Node.js and npm if not present
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Installing Node.js and npm...${NC}"
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
       echo -e "${YELLOW}Waiting for package manager...${NC}"
       sleep 3
    done
    apt-get update
    apt-get install -y nodejs npm
else
    echo -e "${GREEN}✓ Node.js already installed ($(node --version))${NC}"
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

KEYS=$(node /tmp/generate-jwt.js "$JWT_SECRET")
ANON_KEY=$(echo "$KEYS" | grep ANON_KEY | cut -d'=' -f2)
SERVICE_ROLE_KEY=$(echo "$KEYS" | grep SERVICE_ROLE_KEY | cut -d'=' -f2)
rm /tmp/generate-jwt.js

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

# Critical: MUST be your-tenant-id
sed -i "s|^POOLER_TENANT_ID=.*|POOLER_TENANT_ID=your-tenant-id|" .env

# Additional settings
sed -i "s|^VAULT_ENC_KEY=.*|VAULT_ENC_KEY=$VAULT_ENC_KEY|" .env
grep -q "SECRET_KEY_BASE" .env || echo "SECRET_KEY_BASE=$SECRET_KEY_BASE" >> .env

# Email settings
sed -i "s|^SMTP_ADMIN_EMAIL=.*|SMTP_ADMIN_EMAIL=$EMAIL|" .env
sed -i "s|^SMTP_HOST=.*|SMTP_HOST=smtp.gmail.com|" .env
sed -i "s|^SMTP_PORT=.*|SMTP_PORT=587|" .env
sed -i "s|^SMTP_USER=.*|SMTP_USER=$EMAIL|" .env
sed -i "s|^SMTP_SENDER_NAME=.*|SMTP_SENDER_NAME=Supabase|" .env

# Add additional configurations
cat >> .env << 'ENVEOF'

# Realtime Configuration
REALTIME_IP_VERSION=IPv4
REALTIME_PORT=4000
REALTIME_SOCKET_TIMEOUT=7200000
REALTIME_HEARTBEAT_INTERVAL=30000
REALTIME_HEARTBEAT_TIMEOUT=60000
REALTIME_MAX_EVENTS_PER_SECOND=100

# Functions
FUNCTIONS_VERIFY_JWT=true

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
ENVEOF

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

with open('docker-compose.yml', 'r') as f:
   data = yaml.safe_load(f)

# Add ENV variables to functions service
if 'functions' in data['services']:
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

with open('docker-compose.yml', 'w') as f:
   yaml.dump(data, f, default_flow_style=False, sort_keys=False)
PYTHONEOF

# If Python fails, use manual method
if [ $? -ne 0 ]; then
   echo -e "${YELLOW}Python method failed, using manual edit...${NC}"
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
     cpuTimeSoftLimitMs: 1000,
     cpuTimeHardLimitMs: 2000,
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

# n8n-proxy - PUBLIC endpoint (fixed version without Supabase client issues)
cat > volumes/functions/n8n-proxy/index.ts << 'EOF'
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

const corsHeaders = {
 'Access-Control-Allow-Origin': '*',
 'Access-Control-Allow-Headers': '*',
}

// Rate limiting
const rateLimitMap = new Map<string, number>()
const RATE_LIMIT_MS = 1000
const MAX_ENTRIES = 1000

serve(async (req: Request) => {
 if (req.method === 'OPTIONS') {
   return new Response('ok', { headers: corsHeaders })
 }
 
 try {
   // Collect metadata
   const authHeader = req.headers.get('Authorization')
   const sessionId = req.headers.get('X-Session-ID')
   const clientIp = req.headers.get('x-real-ip') || 
                    req.headers.get('x-forwarded-for')?.split(',')[0] || 
                    'unknown'
   const identifier = sessionId || clientIp
   
   // Rate limiting - check requests per second
   const now = Date.now()
   const lastCall = rateLimitMap.get(identifier) || 0
   
   if (now - lastCall < RATE_LIMIT_MS) {
     return new Response(
       JSON.stringify({ error: 'Too many requests. Please wait.' }),
       { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
     )
   }
   
   rateLimitMap.set(identifier, now)
   
   // Clean old entries (1% chance)
   if (Math.random() < 0.01) {
     const cutoff = now - 10000
     for (const [key, time] of rateLimitMap) {
       if (time < cutoff) rateLimitMap.delete(key)
     }
     if (rateLimitMap.size > MAX_ENTRIES) {
       rateLimitMap.clear()
     }
   }
   
   const body = await req.json()
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
   
   // All metadata for n8n
   const enrichedBody = {
     ...body,
     session_id: sessionId || null,
     has_auth: !!authHeader,
     client_ip: clientIp,
     identifier: identifier,
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

# Protected webhook endpoints
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
   
   const body = await req.json()
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
   
   const enrichedBody = {
     ...body,
     source: 'authenticated',
     function: FUNCTION_NAME,
     user_id: user.id,
     user_email: user.email,
     timestamp: new Date().toISOString()
   }
   
   const webhookResponse = await fetch(webhookUrl, {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       ...(webhookAuth ? { 'Authorization': webhookAuth } : {})
     },
     body: JSON.stringify(enrichedBody)
   })
   
   const responseText = await webhookResponse.text()
   
   return new Response(responseText, { 
     headers: { ...corsHeaders, 'Content-Type': 'application/json' },
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

# Nginx initial setup
echo -e "${YELLOW}Setting up Nginx...${NC}"
cat > /etc/nginx/sites-available/$DOMAIN << NGINX
server {
   listen 80;
   server_name $DOMAIN;
   location / { return 200 "OK"; }
}
NGINX

ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# Get SSL certificate
echo -e "${YELLOW}Obtaining SSL certificate...${NC}"
certbot certonly --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL || true

# Final Nginx configuration
cat > /etc/nginx/sites-available/$DOMAIN << NGINX
server {
   server_name $DOMAIN;
   client_max_body_size 100M;
   
   # Critical for Realtime WebSocket
   location /realtime/ {
       proxy_pass http://localhost:8000;
       proxy_http_version 1.1;
       proxy_set_header Upgrade \$http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_set_header Host \$host;
       proxy_set_header X-Real-IP \$remote_addr;
       proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto https;
       proxy_buffering off;
       proxy_cache off;
       proxy_connect_timeout 86400s;
       proxy_read_timeout 86400s;
       proxy_send_timeout 86400s;
       keepalive_timeout 86400s;
       add_header X-Firefox-Spdy "h2=0" always;
   }
   
   location / {
       proxy_pass http://localhost:8000;
       proxy_http_version 1.1;
       proxy_set_header Upgrade \$http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_set_header Host \$host;
       proxy_set_header X-Real-IP \$remote_addr;
       proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto https;
       proxy_read_timeout 86400s;
       proxy_send_timeout 86400s;
   }
   
   listen 443 ssl;
   ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
   ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
   include /etc/letsencrypt/options-ssl-nginx.conf;
   ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
   listen 80;
   server_name $DOMAIN;
   return 301 https://\$host\$request_uri;
}
NGINX

systemctl reload nginx

# Start Docker containers
echo -e "${YELLOW}Starting Docker containers...${NC}"
# Use docker compose v2 if available, otherwise docker-compose
if docker compose version &> /dev/null 2>&1; then
    docker compose up -d
else
    docker-compose up -d
fi

echo -e "${YELLOW}Waiting for services to start (60 seconds)...${NC}"
sleep 60

# Create function_logs table
echo -e "${YELLOW}Creating database tables...${NC}"
docker exec supabase-db psql -U postgres -d postgres -c "
CREATE TABLE IF NOT EXISTS public.function_logs (
   user_id UUID NOT NULL,
   function_name TEXT NOT NULL,
   last_called_at TIMESTAMPTZ DEFAULT NOW(),
   PRIMARY KEY (user_id, function_name)
);
ALTER TABLE public.function_logs ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_function_logs_lookup ON function_logs(user_id, function_name, last_called_at);" 2>/dev/null || true

# Save credentials
cat > /root/supabase-credentials.txt << CREDS
========================================
SUPABASE INSTALLATION COMPLETE
========================================

Main URL: https://$DOMAIN
Studio: https://$DOMAIN/studio
Username: supabase
Password: $DASHBOARD_PASSWORD

Database Connection (via pooler):
 Host: $DOMAIN
 Port: 5432
 Username: postgres.your-tenant-id
 Password: $POSTGRES_PASSWORD
 Database: postgres

API Keys:
 Anon: $ANON_KEY
 Service: $SERVICE_ROLE_KEY

Edge Functions:
 Public/Hybrid: https://$DOMAIN/functions/v1/n8n-proxy
 Protected #1: https://$DOMAIN/functions/v1/webhook-endpoint-1
 Protected #2: https://$DOMAIN/functions/v1/webhook-endpoint-2
 Protected #3: https://$DOMAIN/functions/v1/webhook-endpoint-3

WebSocket Test:
 const ws = new WebSocket('wss://$DOMAIN/realtime/v1/websocket?apikey=$ANON_KEY&vsn=1.0.0');
 ws.onopen = () => console.log('Realtime connected!');

========================================
IMPORTANT: AFTER CONFIGURING WEBHOOKS
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
QUICK RESTART COMMANDS
========================================

# Restart only functions (faster):
cd /opt/supabase-project
docker-compose restart functions

# Full restart (if functions don't update):
cd /opt/supabase-project
docker-compose down && docker-compose up -d

# Check logs:
docker logs supabase-edge-functions --tail 50

========================================
CREDS

# Final check and instructions
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}INSTALLATION COMPLETE!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Credentials saved to: /root/supabase-credentials.txt${NC}"
echo ""
echo -e "${RED}========================================${NC}"
echo -e "${RED}IMPORTANT: CONFIGURE YOUR WEBHOOKS NOW${NC}"
echo -e "${RED}========================================${NC}"
echo ""
echo -e "${YELLOW}Step 1: Edit configuration file:${NC}"
echo "   nano /opt/supabase-project/.env"
echo ""
echo -e "${YELLOW}Step 2: Add your webhook URLs:${NC}"
echo "   N8N_WEBHOOK_URL=https://your-n8n.com/webhook/xxx"
echo "   N8N_BASIC_AUTH_HEADER=Basic base64_encoded_user:pass"
echo ""
echo -e "${YELLOW}Step 3: RESTART containers to apply changes:${NC}"
echo -e "${GREEN}   cd /opt/supabase-project${NC}"
echo -e "${GREEN}   docker-compose down && docker-compose up -d${NC}"
echo ""
echo -e "${YELLOW}Step 4: Wait 30 seconds, then test:${NC}"
echo "   curl -X POST https://$DOMAIN/functions/v1/n8n-proxy \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -H \"X-Session-ID: test-123\" \\"
echo "     -d '{\"test\": \"data\"}'"
echo ""
