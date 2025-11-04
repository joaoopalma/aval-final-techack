"""
Módulo para verificação de phishing (Opção 3)

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


def _check_redirects(url: str, timeout: int = 6) -> Dict[str, Any]:
    if requests is None:
        return {'available': False, 'error': 'requests not installed'}

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        history = [h.status_code for h in r.history]
        final = r.status_code
        return {'available': True, 'history_status': history, 'final_status': final, 'final_url': r.url}
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
