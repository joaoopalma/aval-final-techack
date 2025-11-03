"""
Testes para o módulo de pré-processamento
"""

import unittest
import pandas as pd
import sys
import os

# Adicionar o diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils.preprocessor import DataPreprocessor


class TestDataPreprocessor(unittest.TestCase):
    """
    Testes para a classe DataPreprocessor
    """
    
    def setUp(self):
        """
        Configuração antes de cada teste
        """
        self.preprocessor = DataPreprocessor()
        
        # Dados de exemplo
        self.sample_data = pd.DataFrame([
            {'ip': '192.168.1.1', 'method': 'GET', 'path': '/index.html', 
             'status': 200, 'size': 1234, 'query_params': '', 'num_params': 0,
             'timestamp': '2025-10-28 10:00:00'},
            {'ip': '192.168.1.2', 'method': 'POST', 'path': '/login', 
             'status': 200, 'size': 567, 'query_params': '', 'num_params': 0,
             'timestamp': '2025-10-28 10:01:00'},
            {'ip': '10.0.0.1', 'method': 'GET', 'path': '/admin/../etc/passwd', 
             'status': 404, 'size': 178, 'query_params': '', 'num_params': 0,
             'timestamp': '2025-10-28 10:02:00'},
        ])
    
    def test_load_data(self):
        """
        Testa carregamento de dados
        """
        result = self.preprocessor.load_data(self.sample_data)
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)
    
    def test_remove_duplicates(self):
        """
        Testa remoção de duplicatas
        """
        # Adicionar duplicata
        data_with_dup = pd.concat([self.sample_data, self.sample_data.iloc[[0]]], ignore_index=True)
        
        self.preprocessor.load_data(data_with_dup)
        result = self.preprocessor.remove_duplicates()
        
        self.assertEqual(len(result), 3)  # Deve remover a duplicata
    
    def test_generate_features(self):
        """
        Testa geração de atributos
        """
        self.preprocessor.load_data(self.sample_data)
        result = self.preprocessor.generate_features()
        
        # Verificar se novos atributos foram criados
        self.assertIn('path_length', result.columns)
        self.assertIn('path_depth', result.columns)
        self.assertIn('has_extension', result.columns)
        self.assertIn('status_category', result.columns)
        self.assertIn('suspicious_chars', result.columns)
    
    def test_detect_suspicious_chars(self):
        """
        Testa detecção de caracteres suspeitos
        """
        # Path normal
        count1 = self.preprocessor._detect_suspicious_chars('/index.html')
        self.assertEqual(count1, 0)
        
        # Path com path traversal
        count2 = self.preprocessor._detect_suspicious_chars('/admin/../etc/passwd')
        self.assertGreater(count2, 0)
        
        # Path com possível XSS
        count3 = self.preprocessor._detect_suspicious_chars('/search?q=<script>alert(1)</script>')
        self.assertGreater(count3, 0)
    
    def test_categorize_status(self):
        """
        Testa categorização de status HTTP
        """
        self.assertEqual(self.preprocessor._categorize_status(200), 'success')
        self.assertEqual(self.preprocessor._categorize_status(301), 'redirect')
        self.assertEqual(self.preprocessor._categorize_status(404), 'client_error')
        self.assertEqual(self.preprocessor._categorize_status(500), 'server_error')


if __name__ == '__main__':
    print("="*70)
    print("🧪 Executando Testes do Preprocessor")
    print("="*70 + "\n")
    
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    print("\n" + "="*70)
    print("✅ Testes Concluídos!")
    print("="*70)
