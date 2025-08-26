[здесь будет содержимое установщика из артефакта]
EOF'

# Создаем README
cat > README.md << 'EOF'
# Supabase Self-Hosted Production Installer v3.1

Production-ready installer for self-hosted Supabase with Edge Functions and N8N integration.

## Features
- ✅ Full Supabase stack (PostgreSQL, Auth, Storage, Realtime, Functions)
- ✅ Edge Functions with public and protected endpoints
- ✅ N8N webhook integration
- ✅ WebSocket Realtime support
- ✅ Automatic SSL with Let's Encrypt
- ✅ Rate limiting
- ✅ CORS configured

## Quick Install

```bash
wget https://raw.githubusercontent.com/Igor-Nersisyan/supabase-installer/main/install-supabase.sh
chmod +x install-supabase.sh
sudo ./install-supabase.sh
Requirements

Ubuntu 22.04+ or Debian 11+
Domain pointing to your server
Root access
Ports 80, 443, 5432 open

Post-Installation

Configure webhooks in /opt/supabase-project/.env
Restart containers: cd /opt/supabase-project && docker-compose down && docker-compose up -d
Access Studio at https://YOUR-DOMAIN/studio

Edge Functions Endpoints

/functions/v1/n8n-proxy - Public webhook proxy
/functions/v1/webhook-endpoint-1 - Protected (requires auth)
/functions/v1/webhook-endpoint-2 - Protected (requires auth)
/functions/v1/webhook-endpoint-3 - Protected (requires auth)

License
MIT
