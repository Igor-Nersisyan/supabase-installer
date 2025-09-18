# Supabase Self-Hosted Production Installer

🚀 **Complete production-ready Supabase installation**

[![Version](https://img.shields.io/badge/version-3.8-blue.svg)](https://github.com/Igor-Nersisyan/supabase-installer)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%20|%2022.04%20|%2024.04-orange.svg)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🎯 What is this?

A battle-tested installer that deploys self-hosted Supabase with enterprise features and critical production fixes. Solves common issues like Edge Functions DNS failures and Kong 60-second timeout limits.

## ✨ Features

### Core Infrastructure
- 🐘 **PostgreSQL 15** with connection pooler
- 🚀 **Kong API Gateway** with fixed 5-minute timeouts
- 🔐 **GoTrue Authentication** service
- 📦 **Storage API** with 5GB file support
- ⚡ **Realtime** websocket server
- 🔧 **Edge Functions** with Deno runtime
- 📊 **Vector logs aggregation**
- 🎨 **Studio** database management UI

### Production Optimizations
- 🔒 **SSL/HTTPS** with Let's Encrypt auto-renewal
- 🛡️ **Nginx reverse proxy** with optimized configs
- 🔥 **UFW firewall** auto-configuration
- 📝 **Log rotation** (10MB per container, 7-day retention)
- 🌐 **DNS configuration** for stable Edge Functions
- 🔐 **Database hardening script** included

### Custom Edge Functions
Pre-configured Edge Functions for integrations:
- `n8n-proxy` - Public webhook endpoint for n8n workflows
- `webhook-endpoint-1/2/3` - Protected authenticated endpoints
- `hello` - Test function to verify setup

## 📋 Requirements

- **OS**: Ubuntu 20.04, 22.04, or 24.04
- **RAM**: Minimum 3GB (4GB+ recommended)
- **CPU**: 2+ cores
- **Storage**: 20GB+ free space
- **Network**:
  - Root access
  - Public IP address
  - Domain name with A record pointing to server
  - Ports: 80, 443, 5432 (PostgreSQL)

## 🚀 Quick Install

```bash
# Download installer
wget https://raw.githubusercontent.com/Igor-Nersisyan/supabase-installer/main/install-supabase.sh

# Make executable
chmod +x install-supabase.sh

# Run as root
sudo ./install-supabase.sh
```

You'll be prompted for:
- Domain name (e.g., `supabase.example.com`)
- Email address (for SSL certificates)

## 📁 Installation Structure

```
/opt/supabase-project/
├── docker-compose.yml       # Container orchestration
├── .env                     # All passwords & configuration
├── volumes/
│   ├── api/                # Kong API gateway config
│   │   └── kong.yml        # Routes and timeouts
│   ├── db/                 # PostgreSQL data
│   │   ├── data/           # Database files
│   │   └── init/           # Initialization scripts
│   ├── functions/          # Edge Functions
│   │   ├── main/           # Router function
│   │   ├── n8n-proxy/      # Public webhook
│   │   ├── webhook-endpoint-1/2/3/  # Protected endpoints
│   │   └── _shared/        # Shared modules
│   ├── logs/               # Vector log config
│   └── storage/            # File storage

/root/
├── supabase-credentials.txt     # All passwords & keys
└── harden_supabase_db.sh       # Database security script
```

## 🛠️ Management Commands

### Service Control

```bash
# View all services status
cd /opt/supabase-project && docker compose ps

# Restart all services
cd /opt/supabase-project && docker compose restart

# Stop everything
cd /opt/supabase-project && docker compose down

# Start everything
cd /opt/supabase-project && docker compose up -d

# View logs for specific service
docker logs supabase-edge-functions --tail 50
docker logs supabase-kong --tail 50
docker logs supabase-db --tail 50
```

### Edge Functions Management

```bash
# Restart only Edge Functions (faster)
cd /opt/supabase-project
docker compose restart functions

# Full restart if functions don't update
docker compose down && docker compose up -d

# Check functions logs
docker logs supabase-edge-functions --tail 50 -f

# Test public function
curl https://your-domain.com/functions/v1/hello
```

### Database Management

```bash
# Connect to PostgreSQL
docker exec -it supabase-db psql -U postgres

# Backup database
docker exec supabase-db pg_dump -U postgres > backup.sql

# Check connections
docker exec supabase-db psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"
```

### Log Management

```bash
# Check log sizes
du -sh /var/lib/docker/containers/*/*-json.log | sort -h

# Force log rotation
logrotate -f /etc/logrotate.d/docker-containers

# View aggregated logs
docker logs supabase-vector --tail 100
```

## 🔧 Configuration

### Access Credentials
All credentials saved in `/root/supabase-credentials.txt`:
- Studio URL: `https://your-domain.com/studio`
- Database connection details
- API keys (anon & service)
- Dashboard password

### Environment Variables
Configuration in `/opt/supabase-project/.env`:
- Database passwords
- JWT secrets
- API URLs
- SMTP settings
- Webhook URLs for Edge Functions

### Kong Timeouts
Pre-configured in `volumes/api/kong.yml`:
- Functions: 5 minutes (300 seconds)
- Storage: 10 minutes
- Realtime: 1 hour
- Default: 60 seconds

### Edge Functions Setup

To configure webhook endpoints, edit `.env`:

```bash
# n8n webhook (public)
N8N_WEBHOOK_URL=https://your-n8n.com/webhook/xxx
N8N_BASIC_AUTH_HEADER=Basic base64_encoded_credentials

# Protected endpoints
ENDPOINT_1_WEBHOOK_URL=https://your-service.com/webhook
ENDPOINT_1_AUTH_HEADER=Bearer your-token
```

Then restart functions:
```bash
cd /opt/supabase-project
docker compose restart functions
```

## 🐛 Troubleshooting

### Edge Functions not working

```bash
# Check DNS configuration
docker exec supabase-edge-functions nslookup google.com

# Verify functions are loaded
docker logs supabase-edge-functions --tail 100 | grep "Booted"

# Test function directly
curl -i https://your-domain.com/functions/v1/hello
```

### Kong timeout issues

```bash
# Verify timeout settings
docker exec supabase-kong cat /var/run/kong/kong.yml | grep timeout

# Check Kong routes
curl http://localhost:8001/services/functions-v1
```

### Database connection issues

```bash
# Test pooler connection
psql postgresql://postgres.postgres:password@your-domain.com:5432/postgres

# Check if port 5432 is open
netstat -tulpn | grep 5432
```

### High memory usage

```bash
# Check container resources
docker stats --no-stream

# Restart heavy services
docker compose restart storage
docker compose restart functions
```

### Studio not loading

```bash
# Check if all services are healthy
cd /opt/supabase-project
docker compose ps

# Restart Studio
docker compose restart studio
```

## 📊 Resource Usage

Typical consumption with moderate load:
- **RAM**: 2.5-3.5GB total
  - PostgreSQL: 500MB-1GB
  - Edge Functions: 300-500MB
  - Kong: 200-300MB
  - Others: 100-200MB each
- **CPU**: 10-30% average
- **Disk**: 2-5GB base + your data
- **Network**: Varies by usage

## 🔒 Security Hardening

### Restrict Database Access

After installation, run the hardening script:

```bash
# Run hardening script
bash /root/harden_supabase_db.sh

# Enter trusted IP addresses when prompted
# This restricts PostgreSQL port 5432 to specific IPs only
```

### Additional Security Steps

```bash
# Remove credentials file after saving elsewhere
rm /root/supabase-credentials.txt

# Enable fail2ban for SSH protection
apt install fail2ban -y

# Disable root SSH (use sudo user instead)
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh
```

## 🔄 Updates

### Update Supabase Components

```bash
cd /opt/supabase-project
docker compose pull
docker compose down
docker compose up -d
```

### Update Installer

```bash
wget https://raw.githubusercontent.com/Igor-Nersisyan/supabase-installer/main/install-supabase.sh -O install-supabase-new.sh
# Review changes before using
```

## 🏗️ Architecture

```
Internet
    ↓
Nginx (SSL/443)
    ↓
Kong Gateway (8000)
    ├── /auth → GoTrue (9999)
    ├── /rest → PostgREST (3000)
    ├── /realtime → Realtime (4000)
    ├── /storage → Storage (5000)
    ├── /functions → Edge Functions (3001)
    └── /studio → Studio (3002)
         ↓
PostgreSQL (5432)
    └── Pooler (6543)
```

## 💡 Tips & Best Practices

1. **Always backup before updates**
2. **Monitor disk space** - logs and storage can grow
3. **Use connection pooler** for production apps
4. **Set up monitoring** - use `/status` endpoint
5. **Configure email** - edit SMTP settings in `.env`
6. **Secure your database** - run hardening script
7. **Test Edge Functions** locally before deploying

## 🤝 Contributing

Found issues or have improvements? Please open an issue or submit a PR!

## 📄 License

MIT License - free to use in any project

## ⭐ Support

If this installer saved you hours of debugging, consider giving it a star on GitHub!

---

**Note**: This is an independent project, not officially affiliated with Supabase Inc.
