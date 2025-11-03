"""
Testes básicos para o módulo Scanner
"""

import unittest
import os
import sys

# Adicionar o diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner import LogScanner


class TestLogScanner(unittest.TestCase):
    """
    Testes para a classe LogScanner
    """
    
    def setUp(self):
        """
        Configuração antes de cada teste
        """
        self.scanner = LogScanner()
    
    def test_scanner_initialization(self):
        """
        Testa se o scanner é inicializado corretamente
        """
        self.assertIsNotNone(self.scanner)
        self.assertEqual(len(self.scanner.logs_data), 0)
    
    def test_parse_valid_log_line(self):
        """
        Testa o parse de uma linha válida de log
        """
        log_line = '192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234'
        
        result = self.scanner.parse_log_line(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '192.168.1.100')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['path'], '/index.html')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['size'], 1234)
    
    def test_parse_log_with_params(self):
        """
        Testa o parse de log com parâmetros na URL
        """
        log_line = '10.0.0.1 - - [28/Oct/2025:10:00:00 +0000] "GET /search?q=test&lang=en HTTP/1.1" 200 500'
        
        result = self.scanner.parse_log_line(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['path'], '/search')
        self.assertEqual(result['query_params'], 'q=test&lang=en')
        self.assertEqual(result['num_params'], 2)
    
    def test_parse_invalid_log_line(self):
        """
        Testa o parse de uma linha inválida
        """
        log_line = 'This is not a valid log line'
        
        result = self.scanner.parse_log_line(log_line)
        
        self.assertIsNone(result)
    
    def test_collect_logs_from_text(self):
        """
        Testa coleta de logs de texto
        """
        log_text = '''192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [28/Oct/2025:10:16:45 +0000] "POST /login HTTP/1.1" 200 567'''
        
        logs = self.scanner.collect_logs_from_text(log_text)
        
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]['ip'], '192.168.1.100')
        self.assertEqual(logs[1]['method'], 'POST')
    
    def test_get_statistics(self):
        """
        Testa geração de estatísticas
        """
        log_text = '''192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.100 - - [28/Oct/2025:10:16:45 +0000] "POST /login HTTP/1.1" 200 567
192.168.1.101 - - [28/Oct/2025:10:17:22 +0000] "GET /admin HTTP/1.1" 403 100'''
        
        self.scanner.collect_logs_from_text(log_text)
        stats = self.scanner.get_statistics()
        
        self.assertEqual(stats['total_requests'], 3)
        self.assertEqual(stats['unique_ips'], 2)
        self.assertIn('GET', stats['methods'])
        self.assertIn('POST', stats['methods'])


def run_tests():
    """
    Executa todos os testes
    """
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == '__main__':
    print("="*70)
    print("🧪 Executando Testes do Sistema")
    print("="*70 + "\n")
    
    run_tests()
    
    print("\n" + "="*70)
    print("✅ Testes Concluídos!")
    print("="*70)
