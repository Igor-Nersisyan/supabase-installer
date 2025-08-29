#!/bin/bash
# Supabase Self-Hosted Production Installer v3.2
# With dependency checks and firewall configuration

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Supabase Self-Hosted Installer v3.2${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Check root
if [ "$EUID" -ne 0 ]; then 
   echo -e "${RED}Запустите с sudo:${NC}"
   echo "sudo ./install-supabase.sh"
   exit 1
fi

# Check RAM
RAM=$(free -m | awk 'NR==2{print $2}')
if [ $RAM -lt 1500 ]; then
    echo -e "${RED}ОШИБКА: Недостаточно памяти${NC}"
    echo "Требуется минимум 2GB RAM, у вас: ${RAM}MB"
    exit 1
fi

# Wait for apt locks
echo -e "${YELLOW}Проверка блокировок apt...${NC}"
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    echo "Ждем завершения других установок..."
    sleep 3
done

# Update package list
echo -e "${YELLOW}Обновление списка пакетов...${NC}"
apt-get update -qq

# Install basic tools first
echo -e "${YELLOW}Установка базовых инструментов...${NC}"
apt-get install -y curl wget software-properties-common apt-transport-https ca-certificates gnupg lsb-release lsof

# Check and install dependencies
echo -e "${YELLOW}Проверка и установка зависимостей...${NC}"

# Docker
if ! command -v docker &> /dev/null; then
    echo "Установка Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "✓ Docker уже установлен"
fi

# Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "Установка Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
else
    echo "✓ Docker Compose уже установлен"
fi

# Git
if ! command -v git &> /dev/null; then
    echo "Установка Git..."
    apt-get install -y git
else
    echo "✓ Git уже установлен"
fi

# Node.js and npm
if ! command -v node &> /dev/null; then
    echo "Установка Node.js и npm..."
    apt-get install -y nodejs npm
else
    echo "✓ Node.js уже установлен"
fi

# Python3 and yaml
if ! command -v python3 &> /dev/null; then
    echo "Установка Python3..."
    apt-get install -y python3 python3-pip
else
    echo "✓ Python3 уже установлен"
fi

# Install python yaml module
python3 -m pip install pyyaml 2>/dev/null || pip3 install pyyaml 2>/dev/null || apt-get install -y python3-yaml

# Nginx
if ! command -v nginx &> /dev/null; then
    echo "Установка Nginx..."
    apt-get install -y nginx
else
    echo "✓ Nginx уже установлен"
fi

# Certbot
if ! command -v certbot &> /dev/null; then
    echo "Установка Certbot..."
    apt-get install -y certbot python3-certbot-nginx
else
    echo "✓ Certbot уже установлен"
fi

# Other tools
for tool in openssl dig nano; do
    if ! command -v $tool &> /dev/null; then
        echo "Установка $tool..."
        case $tool in
            dig)
                apt-get install -y dnsutils
                ;;
            *)
                apt-get install -y $tool
                ;;
        esac
    fi
done

# Check if ports are busy
echo -e "${YELLOW}Проверка портов...${NC}"
if lsof -Pi :80 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${YELLOW}Порт 80 занят, пытаемся освободить...${NC}"
    systemctl stop apache2 2>/dev/null || true
    systemctl disable apache2 2>/dev/null || true
    
    if lsof -Pi :80 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${RED}ОШИБКА: Не удалось освободить порт 80${NC}"
        echo "Остановите сервис вручную и запустите установщик снова"
        lsof -Pi :80 -sTCP:LISTEN
        exit 1
    fi
fi

# Configure firewall
echo -e "${YELLOW}Настройка файрволла...${NC}"
if command -v ufw &> /dev/null; then
    echo "Открываем необходимые порты..."
    ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
    ufw allow 80/tcp comment 'HTTP' 2>/dev/null || true
    ufw allow 443/tcp comment 'HTTPS' 2>/dev/null || true
    ufw allow 5432/tcp comment 'PostgreSQL' 2>/dev/null || true
    
    # Enable firewall if not enabled
    if ufw status | grep -q inactive; then
        echo "y" | ufw enable
    fi
    
    echo "Статус файрволла:"
    ufw status numbered
elif command -v firewall-cmd &> /dev/null; then
    # For CentOS/RHEL
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --permanent --add-port=5432/tcp
    firewall-cmd --reload
else
    echo "Файрволл не обнаружен, пропускаем настройку"
fi

# Input domain and email
echo -e "${GREEN}Все зависимости установлены!${NC}\n"
read -p "Введите домен (например: api.example.com): " DOMAIN

# Check DNS
echo -e "${YELLOW}Проверка DNS...${NC}"
SERVER_IP=$(curl -s ifconfig.me)
DNS_IP=$(dig +short $DOMAIN 2>/dev/null | head -1)

if [ "$SERVER_IP" != "$DNS_IP" ]; then
    echo -e "${YELLOW}ВНИМАНИЕ: DNS возможно не настроен${NC}"
    echo "IP сервера: $SERVER_IP"
    echo "IP домена:  $DNS_IP"
    echo "Убедитесь что A-запись домена указывает на IP сервера"
    read -p "Продолжить установку? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

read -p "Email для SSL сертификата: " EMAIL

# Generate passwords
echo -e "${YELLOW}Генерация паролей...${NC}"
POSTGRES_PASSWORD=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
DASHBOARD_PASSWORD=$(openssl rand -hex 16)
SECRET_KEY_BASE=$(openssl rand -hex 32)
VAULT_ENC_KEY=$(openssl rand -hex 16)

# Clone Supabase
echo -e "${YELLOW}Загрузка Supabase...${NC}"
cd /opt
rm -rf supabase-project
git clone --depth 1 https://github.com/supabase/supabase.git
mkdir -p supabase-project
cp -r supabase/docker/* supabase-project/
cp supabase/docker/.env.example supabase-project/.env
cd supabase-project

# Fix docker-compose.yml for older versions
sed -i '/^name:/d' docker-compose.yml 2>/dev/null || true
sed -i 's/: true/: "true"/g' docker-compose.yml
sed -i 's/: false/: "false"/g' docker-compose.yml

# Generate JWT keys
echo -e "${YELLOW}Генерация JWT ключей...${NC}"
cat > /tmp/generate-jwt.js << EOF
const crypto = require('crypto');
const JWT_SECRET = '$JWT_SECRET';

function signJWT(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', secret).update(\`\${encodedHeader}.\${encodedPayload}\`).digest('base64url');
    return \`\${encodedHeader}.\${encodedPayload}.\${signature}\`;
}

const now = Math.floor(Date.now() / 1000);
const exp = now + (60 * 60 * 24 * 365 * 10);

const anonPayload = { role: 'anon', iss: 'supabase', iat: now, exp: exp };
const servicePayload = { role: 'service_role', iss: 'supabase', iat: now, exp: exp };

console.log('ANON_KEY=' + signJWT(anonPayload, JWT_SECRET));
console.log('SERVICE_ROLE_KEY=' + signJWT(servicePayload, JWT_SECRET));
EOF

KEYS=$(node /tmp/generate-jwt.js)
ANON_KEY=$(echo "$KEYS" | grep ANON_KEY | cut -d'=' -f2)
SERVICE_ROLE_KEY=$(echo "$KEYS" | grep SERVICE_ROLE_KEY | cut -d'=' -f2)
rm /tmp/generate-jwt.js

# Configure .env
echo -e "${YELLOW}Настройка переменных окружения...${NC}"
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" .env
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" .env
sed -i "s|^ANON_KEY=.*|ANON_KEY=$ANON_KEY|" .env
sed -i "s|^SERVICE_ROLE_KEY=.*|SERVICE_ROLE_KEY=$SERVICE_ROLE_KEY|" .env
sed -i "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD|" .env
sed -i "s|^SITE_URL=.*|SITE_URL=https://$DOMAIN|" .env
sed -i "s|^API_EXTERNAL_URL=.*|API_EXTERNAL_URL=https://$DOMAIN|" .env
sed -i "s|^SUPABASE_PUBLIC_URL=.*|SUPABASE_PUBLIC_URL=https://$DOMAIN|" .env
sed -i "s|^POOLER_TENANT_ID=.*|POOLER_TENANT_ID=your-tenant-id|" .env
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
echo -e "${YELLOW}Создание конфигурации логов...${NC}"
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
echo -e "${YELLOW}Добавление переменных в docker-compose.yml...${NC}"
python3 << 'PYTHONEOF'
import yaml
import sys

try:
    with open('docker-compose.yml', 'r') as f:
        data = yaml.safe_load(f)

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
    print("✓ Переменные добавлены в docker-compose.yml")
except Exception as e:
    print(f"Ошибка при обработке docker-compose.yml: {e}")
    sys.exit(1)
PYTHONEOF

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Python метод не сработал, добавьте вручную в docker-compose.yml:${NC}"
    echo "В секцию functions -> environment:"
    echo "  N8N_WEBHOOK_URL: \${N8N_WEBHOOK_URL}"
    echo "  N8N_BASIC_AUTH_HEADER: \${N8N_BASIC_AUTH_HEADER}"
fi

# Create Edge Functions
echo -e "${YELLOW}Создание Edge Functions...${NC}"
mkdir -p volumes/functions/{n8n-proxy,webhook-endpoint-1,webhook-endpoint-2,webhook-endpoint-3,_shared,main,hello}

# Shared CORS
cat > volumes/functions/_shared/cors.ts << 'EOF'
export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-session-id',
}
EOF

# Main function with public endpoint detection
cat > volumes/functions/main/index.ts << 'EOF'
import { serve } from 'https://deno.land/std@0.131.0/http/server.ts'
import * as jose from 'https://deno.land/x/jose@v4.14.4/index.ts'

console.log('main function started')

const JWT_SECRET = Deno.env.get('JWT_SECRET')
const VERIFY_JWT = Deno.env.get('VERIFY_JWT') === 'true'

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
  
  const isPublicEndpoint = PUBLIC_ENDPOINTS.includes(function_name)
  
  console.log(`Function ${function_name} is public: ${isPublicEndpoint}`)
  
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

# Hello function
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

# n8n-proxy - PUBLIC endpoint (working version without Supabase client)
cat > volumes/functions/n8n-proxy/index.ts << 'EOF'
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*',
}

const rateLimitMap = new Map<string, number>()
const RATE_LIMIT_MS = 1000
const MAX_ENTRIES = 1000

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }
  
  try {
    const authHeader = req.headers.get('Authorization')
    const sessionId = req.headers.get('X-Session-ID')
    const clientIp = req.headers.get('x-real-ip') || 
                     req.headers.get('x-forwarded-for')?.split(',')[0] || 
                     'unknown'
    const identifier = sessionId || clientIp
    
    const now = Date.now()
    const lastCall = rateLimitMap.get(identifier) || 0
    
    if (now - lastCall < RATE_LIMIT_MS) {
      return new Response(
        JSON.stringify({ error: 'Too many requests. Please wait.' }),
        { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }
    
    rateLimitMap.set(identifier, now)
    
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
echo -e "${YELLOW}Настройка Nginx...${NC}"
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
echo -e "${YELLOW}Получение SSL сертификата...${NC}"
certbot certonly --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL || true

# Final Nginx configuration
cat > /etc/nginx/sites-available/$DOMAIN << NGINX
server {
    server_name $DOMAIN;
    client_max_body_size 100M;
    
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
echo -e "${YELLOW}Запуск Docker контейнеров...${NC}"
docker-compose up -d

echo -e "${YELLOW}Ожидание запуска сервисов (60 секунд)...${NC}"
sleep 60

# Create function_logs table
echo -e "${YELLOW}Создание таблиц в базе данных...${NC}"
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

Database Connection:
  Host: $DOMAIN
  Port: 5432
  Username: postgres.your-tenant-id
  Password: $POSTGRES_PASSWORD
  Database: postgres

API Keys:
  Anon: $ANON_KEY
  Service: $SERVICE_ROLE_KEY

Edge Functions:
  Public: https://$DOMAIN/functions/v1/n8n-proxy
  Test: https://$DOMAIN/functions/v1/hello
  Protected: https://$DOMAIN/functions/v1/webhook-endpoint-1

========================================
IMPORTANT: CONFIGURE WEBHOOKS
========================================

1. Edit .env file:
   nano /opt/supabase-project/.env

2. Add webhook URL:
   N8N_WEBHOOK_URL=https://your-n8n.com/webhook/xxx
   N8N_BASIC_AUTH_HEADER=Basic base64_encoded

3. Restart:
   cd /opt/supabase-project
   docker-compose down && docker-compose up -d

========================================
CREDS

# Final message
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}УСТАНОВКА ЗАВЕРШЕНА!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "URL: https://$DOMAIN"
echo "Studio: https://$DOMAIN/studio"
echo "Пароль: $DASHBOARD_PASSWORD"
echo ""
echo "Полные данные: cat /root/supabase-credentials.txt"
echo ""
echo -e "${YELLOW}Настройте webhook:${NC}"
echo "1. nano /opt/supabase-project/.env"
echo "2. Добавьте N8N_WEBHOOK_URL"
echo "3. cd /opt/supabase-project && docker-compose down && docker-compose up -d"
echo ""
echo -e "${GREEN}Тест:${NC}"
echo "curl -X POST https://$DOMAIN/functions/v1/hello"
echo "wscat -c \"wss://$DOMAIN/realtime/v1/websocket?apikey=$ANON_KEY&vsn=1.0.0\""
echo ""
