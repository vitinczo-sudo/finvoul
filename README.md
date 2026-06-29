# FinVault — Guia de Deploy em Produção

## Pré-requisitos
- VPS com Ubuntu 22.04+ (mín. 2 vCPU, 4GB RAM)
- Docker + Docker Compose v2
- Domínio com DNS apontando para o servidor
- Conta Google Cloud Console (para OAuth)

---

## 1. Clonar e configurar

```bash
git clone https://github.com/seu-usuario/finvault.git
cd finvault

# Copiar e preencher variáveis de ambiente
cp .env.example .env
nano .env

# Gerar chaves RSA + AES (copie o output para .env)
node scripts/keygen.js
```

## 2. Configurar Google OAuth

1. Acesse https://console.cloud.google.com/apis/credentials
2. Crie um projeto → OAuth 2.0 Client ID → Web application
3. Adicione em "Authorized JavaScript origins": `https://seudominio.com.br`
4. Adicione em "Authorized redirect URIs": `https://seudominio.com.br/api/auth/google`
5. Copie o **Client ID** para `GOOGLE_CLIENT_ID` no `.env`

## 3. Certificado TLS (Let's Encrypt)

```bash
# Primeiro boot — obter certificado
docker run --rm -v $(pwd)/certbot_certs:/etc/letsencrypt \
  -v $(pwd)/certbot_www:/var/www/certbot \
  certbot/certbot certonly --webroot \
  -w /var/www/certbot -d seudominio.com.br \
  --email seu@email.com --agree-tos --no-eff-email
```

## 4. Subir a stack

```bash
# Build + iniciar todos os serviços
docker-compose up -d --build

# Ver logs
docker-compose logs -f app

# Verificar saúde
curl https://seudominio.com.br/health
```

## 5. Deploy do frontend

```bash
# Copiar os arquivos HTML/JS para a pasta servida pelo nginx
mkdir -p frontend
cp finvault-login.html finvault-app.html api.js frontend/

# Substituir variáveis no nginx.conf
sed -i "s/\${DOMAIN}/seudominio.com.br/g" nginx.conf

# Reiniciar nginx
docker-compose restart nginx
```

## 6. Verificações de segurança pós-deploy

```bash
# SSL Labs (deve dar A ou A+)
curl "https://api.ssllabs.com/api/v3/analyze?host=seudominio.com.br"

# Security headers (deve dar A)
curl "https://securityheaders.com/?q=seudominio.com.br&followRedirects=on" -I

# Mozilla Observatory
npx observatory seudominio.com.br
```

## 7. Rodar testes

```bash
# Instalar deps e rodar suite completa
npm install
npm test

# Com cobertura
npm run test:cov
```

## 8. Monitoramento (recomendado)

```bash
# Uptime (grátis): https://uptimerobot.com
# Adicionar monitor HTTP para https://seudominio.com.br/health

# Error tracking: Sentry
# npm install @sentry/node
# Adicionar SENTRY_DSN no .env
```

## 9. Backups

Os backups são executados automaticamente todo dia via o container `backup`.
Para restaurar manualmente:

```bash
# Baixar backup do S3
aws s3 cp s3://finvault-backups/finvault-20250321.sql.gz /tmp/

# Restaurar
gunzip /tmp/finvault-20250321.sql.gz
docker-compose exec -T postgres psql -U finvault_app finvault < /tmp/finvault-20250321.sql
```

## 10. Checklist final antes de go-live

- [ ] `.env` preenchido com valores de produção (nunca usar defaults)
- [ ] Chaves RSA geradas (node scripts/keygen.js)
- [ ] Certificado TLS obtido (A+ no SSL Labs)
- [ ] Google OAuth configurado com domínio de produção
- [ ] `GOOGLE_CLIENT_ID` inserido no `finvault-login.html` (substituir `SEU_GOOGLE_CLIENT_ID`)
- [ ] URL da API configurada em `api.js` (`API_BASE`)
- [ ] Backup S3 testado e funcionando
- [ ] Teste de carga básico (k6 ou Apache Bench)
- [ ] Monitor de uptime configurado
- [ ] DPO designado e documentado (LGPD Art. 41)
- [ ] Política de Privacidade publicada no site

---

## Estrutura de arquivos

```
finvault/
├── server.js          # API completa Node.js/Express
├── server.test.js     # Suite de testes Jest
├── schema.sql         # Schema PostgreSQL completo
├── package.json       # Dependências
├── Dockerfile         # Container da API
├── docker-compose.yml # Stack completa
├── nginx.conf         # Reverse proxy + TLS
├── api.js             # Cliente JS do frontend
├── .env.example       # Template de variáveis
├── scripts/
│   └── keygen.js      # Gerador de chaves RSA+AES
└── frontend/          # Arquivos HTML (gerados)
    ├── finvault-login.html
    └── finvault-app.html
```

## Suporte

- Issues: github.com/seu-usuario/finvault/issues
- LGPD / DPO: dpo@seudominio.com.br
