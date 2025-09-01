# Supabase Self-Hosted Installer

## Installation

```bash
# Download installer
wget https://raw.githubusercontent.com/Igor-Nersisyan/supabase-installer/main/install-supabase.sh

# Make executable
chmod +x install-supabase.sh

# Run as root
sudo ./install-supabase.sh

# Requirements:

Ubuntu 22.04+ or Debian 11+
Domain pointing to your server

After Installation

Configure webhook URLs:

bashnano /opt/supabase-project/.env

Add your webhook URLs:

N8N_WEBHOOK_URL=https://your-n8n.com/webhook/xxx
N8N_BASIC_AUTH_HEADER=Basic base64_encoded_user:pass

Restart containers:

bashcd /opt/supabase-project
docker-compose down && docker-compose up -d

Test endpoint:

bashcurl -X POST https://YOUR-DOMAIN/functions/v1/n8n-proxy \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: test-123" \
  -d '{"test": "data"}'
Credentials
After installation, check credentials:
bashcat /root/supabase-credentials.txt
Access Points

Studio: https://YOUR-DOMAIN/studio

Edge Functions

/functions/v1/n8n-proxy - Public webhook
/functions/v1/hello - Test endpoint
/functions/v1/webhook-endpoint-1 - Protected (requires auth)
/functions/v1/webhook-endpoint-2 - Protected (requires auth)
/functions/v1/webhook-endpoint-3 - Protected (requires auth)
