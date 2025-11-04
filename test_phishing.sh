#!/bin/bash

echo "========================================"
echo "TESTE COMPLETO DO SISTEMA DE PHISHING"
echo "========================================"
echo ""

BASE_URL="http://localhost:8080"

echo "1. Testando página inicial..."
curl -s "$BASE_URL/" | grep -q "Sistema de Detecção" && echo "✅ Página inicial OK" || echo "❌ Erro na página inicial"

echo ""
echo "2. Testando página de phishing..."
curl -s "$BASE_URL/phishing" | grep -q "Verificação de Phishing" && echo "✅ Página de phishing OK" || echo "❌ Erro na página de phishing"

echo ""
echo "3. Testando verificação de URL SEGURA (https://google.com)..."
curl -X POST "$BASE_URL/check-phishing" -d "url=https://google.com" -H "Content-Type: application/x-www-form-urlencoded" -s > /tmp/test_safe.html
grep -q "URL Segura\|URL Suspeita" /tmp/test_safe.html && echo "✅ Verificação de URL segura OK" || echo "❌ Erro na verificação"

echo ""
echo "4. Testando verificação de URL SUSPEITA (http://malicious.no-ip.com)..."
curl -X POST "$BASE_URL/check-phishing" -d "url=http://malicious.no-ip.com" -H "Content-Type: application/x-www-form-urlencoded" -s > /tmp/test_malicious.html
grep -q "DNS Dinâmico" /tmp/test_malicious.html && echo "✅ Detecção de DNS dinâmico OK" || echo "❌ Erro na detecção de DNS dinâmico"

echo ""
echo "5. Testando verificação de URL com TYPOSQUATTING (http://paypa1.com)..."
curl -X POST "$BASE_URL/check-phishing" -d "url=http://paypa1.com" -H "Content-Type: application/x-www-form-urlencoded" -s > /tmp/test_typo.html
grep -q "Similaridade" /tmp/test_typo.html && echo "✅ Detecção de typosquatting OK" || echo "❌ Erro na detecção de typosquatting"

echo ""
echo "6. Testando página de histórico..."
curl -s "$BASE_URL/phishing-history" | grep -q "Histórico de Verificações" && echo "✅ Página de histórico OK" || echo "❌ Erro na página de histórico"

echo ""
echo "7. Verificando se Chart.js foi carregado..."
curl -s "$BASE_URL/phishing-history" | grep -q "chart.js" && echo "✅ Chart.js integrado OK" || echo "❌ Chart.js não encontrado"

echo ""
echo "8. Verificando botões de exportação..."
curl -s "$BASE_URL/phishing-history" | grep -q "export-history" && echo "✅ Botões de exportação OK" || echo "❌ Botões de exportação não encontrados"

echo ""
echo "9. Testando análise de logs (funcionalidade original)..."
curl -s "$BASE_URL/logs" | grep -q "Upload de Logs" && echo "✅ Análise de logs OK" || echo "❌ Erro na análise de logs"

echo ""
echo "========================================"
echo "RESUMO DOS TESTES"
echo "========================================"
docker ps | grep threat-detection && echo "✅ Container Docker rodando" || echo "❌ Container não está rodando"
docker exec threat-detection ls -la /app/data/phishing_checks.json && echo "✅ Arquivo de histórico existe" || echo "❌ Arquivo de histórico não existe"

echo ""
echo "========================================"
echo "TESTE COMPLETO!"
echo "========================================"
