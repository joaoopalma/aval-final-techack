"""

Fornece funções para checar uma URL contra blacklists locais, detectar
características suspeitas, verificar redirects, cert SSL e (se disponível)
consultar WHOIS e analisar conteúdo HTML básico.

Este módulo tenta usar bibliotecas opcionais (whois, bs4). Se ausentes,
algumas verificações serão ignoradas de forma graciosa.
"""

from __future__ import annotations

import os
import json
import re
import socket
import ssl
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from difflib import SequenceMatcher

try:
    import requests
except Exception:
    requests = None  # type: ignore

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None  # type: ignore

try:
    import whois as whois_module
except Exception:
    whois_module = None  # type: ignore

# Blacklist paths
BLACKLIST_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'blacklists')
OPENPHISH_PATH = os.path.join(BLACKLIST_DIR, 'openphish_feed.txt')
PHISHTANK_PATH = os.path.join(BLACKLIST_DIR, 'phishtank_feed.txt')
HISTORY_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'phishing_checks.json')


def _load_blacklist() -> List[str]:
    """Carrega múltiplas blacklists (OpenPhish e PhishTank)"""
    all_urls = []
    
    # Carregar OpenPhish
    if os.path.exists(OPENPHISH_PATH):
        with open(OPENPHISH_PATH, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
            all_urls.extend(lines)
    
    # Carregar PhishTank
    if os.path.exists(PHISHTANK_PATH):
        with open(PHISHTANK_PATH, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
            all_urls.extend(lines)
    
    return all_urls


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


def _detect_suspicious_chars(path_or_url: str) -> int:
    suspicious_patterns = [
        r'\.\.',
        r'<.*>',
        r'script',
        r'union',
        r'select',
        r'drop',
        r'exec',
        r'%',
        r'\\x',
    ]

    count = 0
    txt = (path_or_url or '').lower()
    for p in suspicious_patterns:
        if re.search(p, txt):
            count += 1

    # heuristic: many subdomains
    if txt.count('.') >= 4:
        count += 1

    return count


def _domain_similarity(domain: str, brands: Optional[List[str]] = None) -> Dict[str, float]:
    if not brands:
        brands = ['paypal', 'google', 'facebook', 'apple', 'microsoft', 'amazon', 'bank', 'netflix']

    results = {}
    d = domain.split(':')[0]
    for b in brands:
        score = SequenceMatcher(None, d, b).ratio()
        results[b] = score

    return results


def _check_ssl_cert(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Verifica certificado SSL com análise avançada"""
    info: Dict[str, Any] = {'available': False}
    host = domain.split(':')[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info['available'] = True
                info['issuer'] = cert.get('issuer')
                info['subject'] = cert.get('subject')
                info['notBefore'] = cert.get('notBefore')
                info['notAfter'] = cert.get('notAfter')
                
                # NOVO: Verificar coincidência domínio/certificado
                subject_alt_names = []
                common_name = None
                
                # Extrair Common Name (CN) do subject
                if cert.get('subject'):
                    for rdn in cert['subject']:
                        for attr in rdn:
                            if attr[0] == 'commonName':
                                common_name = attr[1]
                
                # Extrair Subject Alternative Names (SANs)
                if cert.get('subjectAltName'):
                    subject_alt_names = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                
                # Verificar se o domínio coincide
                domain_matches = False
                if common_name and (host == common_name or host.endswith('.' + common_name.lstrip('*.'))):
                    domain_matches = True
                for san in subject_alt_names:
                    if host == san or host.endswith('.' + san.lstrip('*.')):
                        domain_matches = True
                        break
                
                info['common_name'] = common_name
                info['subject_alt_names'] = subject_alt_names
                info['domain_matches'] = domain_matches
                
                # NOVO: Detectar certificado auto-assinado
                issuer_cn = None
                if cert.get('issuer'):
                    for rdn in cert['issuer']:
                        for attr in rdn:
                            if attr[0] == 'commonName':
                                issuer_cn = attr[1]
                
                is_self_signed = (issuer_cn == common_name) if issuer_cn and common_name else False
                info['is_self_signed'] = is_self_signed
                
                # NOVO: Verificar CA confiável (lista básica)
                trusted_cas = [
                    'Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 
                    'GlobalSign', 'Symantec', 'Thawte', 'VeriSign',
                    'GoDaddy', 'Entrust', 'Sectigo', 'Amazon', 'Google'
                ]
                is_trusted_ca = False
                if issuer_cn:
                    for ca in trusted_cas:
                        if ca.lower() in issuer_cn.lower():
                            is_trusted_ca = True
                            break
                
                info['is_trusted_ca'] = is_trusted_ca
                info['issuer_cn'] = issuer_cn
                
    except Exception as e:
        info['error'] = str(e)

    return info


def _whois_age(domain: str) -> Dict[str, Any]:
    if whois_module is None:
        return {'available': False, 'error': 'whois module not installed'}

    try:
        w = whois_module.whois(domain)
        # whois package returns a dict-like with 'creation_date'
        creation = w.creation_date
        return {'available': True, 'creation_date': str(creation)}
    except Exception as e:
        return {'available': False, 'error': str(e)}


def _check_dynamic_dns(domain: str) -> Dict[str, Any]:
    """Verifica se o domínio usa serviços de DNS dinâmico (suspeito)"""
    dynamic_dns_providers = [
        'no-ip.com', 'no-ip.org', 'no-ip.biz', 'noip.com',
        'dyndns.org', 'dyndns.com', 'dyn.com',
        'afraid.org', 'freedns.afraid.org',
        'ddns.net', 'duckdns.org', 'dynu.com',
        'changeip.com', 'dns-dynamic.com',
        'sytes.net', 'zapto.org', 'myftp.org',
        'ddnsking.com', 'servebeer.com', 'servegame.com'
    ]
    
    domain_lower = domain.lower().split(':')[0]  # Remove porta se houver
    
    is_dynamic = False
    provider = None
    
    for ddns_provider in dynamic_dns_providers:
        if ddns_provider in domain_lower:
            is_dynamic = True
            provider = ddns_provider
            break
    
    return {
        'is_dynamic_dns': is_dynamic,
        'provider': provider,
        'risk_level': 'high' if is_dynamic else 'none'
    }


def _check_redirects(url: str, timeout: int = 6) -> Dict[str, Any]:
    """Verifica redirecionamentos com análise de comportamento suspeito"""
    if requests is None:
        return {'available': False, 'error': 'requests not installed'}

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        history = [h.status_code for h in r.history]
        final = r.status_code
        
        # NOVO: Análise avançada de redirects
        original_domain = _domain_from_url(url)
        final_domain = _domain_from_url(r.url) if r.url else original_domain
        
        # Verificar mudança de domínio
        domain_changed = (original_domain != final_domain)
        
        # Verificar múltiplos redirects (>3 é suspeito)
        redirect_count = len(history)
        too_many_redirects = redirect_count > 3
        
        # Rastrear todos os domínios na chain
        redirect_chain_domains = []
        if hasattr(r, 'history'):
            for resp in r.history:
                if resp.url:
                    redirect_chain_domains.append(_domain_from_url(resp.url))
        if r.url:
            redirect_chain_domains.append(final_domain)
        
        # Verificar se algum domínio na chain é suspeito
        suspicious_domains_in_chain = []
        suspicious_indicators = ['.tk', '.ml', '.ga', '.cf', '.gq', 'bit.ly', 'tinyurl', 'shorturl']
        for domain in redirect_chain_domains:
            for indicator in suspicious_indicators:
                if indicator in domain.lower():
                    suspicious_domains_in_chain.append(domain)
                    break
        
        return {
            'available': True,
            'history_status': history,
            'final_status': final,
            'final_url': r.url,
            'redirect_count': redirect_count,
            'domain_changed': domain_changed,
            'original_domain': original_domain,
            'final_domain': final_domain,
            'too_many_redirects': too_many_redirects,
            'redirect_chain_domains': redirect_chain_domains,
            'suspicious_domains_in_chain': suspicious_domains_in_chain,
            'is_suspicious': domain_changed or too_many_redirects or len(suspicious_domains_in_chain) > 0
        }
    except Exception as e:
        return {'available': False, 'error': str(e)}


def _analyze_content_for_forms(url: str, timeout: int = 6) -> Dict[str, Any]:
    if requests is None or BeautifulSoup is None:
        return {'available': False, 'error': 'requests or bs4 not installed'}

    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code >= 400:
            return {'available': True, 'forms_found': 0, 'status': r.status_code}

        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        forms_info = []
        for f in forms:
            inputs = f.find_all('input')
            forms_info.append({'inputs': len(inputs), 'has_password': any(i.get('type') == 'password' for i in inputs)})

        return {'available': True, 'forms_found': len(forms), 'forms': forms_info}
    except Exception as e:
        return {'available': False, 'error': str(e)}


def check_url(url: str) -> Dict[str, Any]:
    """Executa todas as verificações e retorna um dicionário com resultados."""
    result: Dict[str, Any] = {'url': url}

    domain = _domain_from_url(url)
    result['domain'] = domain

    # Blacklist
    blacklist = _load_blacklist()
    blacklisted = False
    blacklisted_matches: List[str] = []
    for entry in blacklist:
        if entry and entry.lower() in url.lower():
            blacklisted = True
            blacklisted_matches.append(entry)

    result['blacklisted'] = blacklisted
    result['blacklist_matches'] = blacklisted_matches

    # Suspicious chars
    result['suspicious_score'] = _detect_suspicious_chars(url)

    # Domain similarity
    result['similarity'] = _domain_similarity(domain)

    # SSL cert (if https)
    if url.startswith('https'):
        result['ssl'] = _check_ssl_cert(domain)
    else:
        result['ssl'] = {'available': False, 'reason': 'not https'}

    # WHOIS
    result['whois'] = _whois_age(domain)
    
    # NOVO: DNS Dinâmico
    result['dynamic_dns'] = _check_dynamic_dns(domain)

    # Redirects and final URL
    result['redirects'] = _check_redirects(url)

    # Content analysis for forms
    result['content_analysis'] = _analyze_content_for_forms(url)

    # Heuristics - simple decision
    reasons = []
    if result['blacklisted']:
        reasons.append('blacklist')
    if result['suspicious_score'] > 0:
        reasons.append('suspicious_patterns')
    if result['content_analysis'].get('forms_found', 0) > 0 and result['content_analysis'].get('forms'):
        # if forms have password fields
        if any(f.get('has_password') for f in result['content_analysis'].get('forms', [])):
            reasons.append('login_form')
    
    # NOVO: Verificar DNS dinâmico
    if result['dynamic_dns'].get('is_dynamic_dns'):
        reasons.append('dynamic_dns')
    
    # NOVO: Verificar SSL suspeito
    if result['ssl'].get('available'):
        if not result['ssl'].get('domain_matches'):
            reasons.append('ssl_domain_mismatch')
        if result['ssl'].get('is_self_signed'):
            reasons.append('ssl_self_signed')
        if not result['ssl'].get('is_trusted_ca'):
            reasons.append('ssl_untrusted_ca')
    
    # NOVO: Verificar redirecionamentos suspeitos
    if result['redirects'].get('is_suspicious'):
        reasons.append('suspicious_redirects')

    result['reasons'] = reasons

    # Save to history
    try:
        history = []
        if os.path.exists(HISTORY_PATH):
            with open(HISTORY_PATH, 'r', encoding='utf-8') as f:
                history = json.load(f)
        history.append(result)
        with open(HISTORY_PATH, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception:
        # não falhar se salvar histórico falhar
        pass

    return result


if __name__ == '__main__':
    # quick demo
    test_url = 'http://example.com'
    print('Checking', test_url)
    r = check_url(test_url)
    print(json.dumps(r, indent=2, ensure_ascii=False))
