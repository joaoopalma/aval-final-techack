"""
Módulo de Pré-processamento de Dados
Responsável pela limpeza e preparação dos dados coletados
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Optional
import re


class DataPreprocessor:
    """
    Classe responsável pelo pré-processamento dos dados de log
    """
    
    def __init__(self):
        """
        Inicializa o preprocessador
        """
        self.df = None
        self.cleaned_df = None
        
    def load_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Carrega os dados para processamento
        
        Args:
            data: DataFrame com os dados brutos
            
        Returns:
            DataFrame carregado
        """
        self.df = data.copy()
        return self.df
    
    def remove_missing_values(self, strategy: str = 'drop') -> pd.DataFrame:
        """
        Remove ou trata valores ausentes
        
        Args:
            strategy: Estratégia ('drop' para remover, 'fill' para preencher)
            
        Returns:
            DataFrame sem valores ausentes
        """
        if self.df is None:
            raise ValueError("Nenhum dado carregado. Use load_data() primeiro.")
        
        initial_count = len(self.df)
        
        if strategy == 'drop':
            # Remove linhas com valores ausentes em colunas críticas
            critical_columns = ['ip', 'method', 'path', 'status']
            self.df = self.df.dropna(subset=critical_columns)
            
        elif strategy == 'fill':
            # Preenche valores ausentes
            self.df['size'] = self.df['size'].fillna(0)
            self.df['query_params'] = self.df['query_params'].fillna('')
            self.df['num_params'] = self.df['num_params'].fillna(0)
        
        removed = initial_count - len(self.df)
        if removed > 0:
            print(f"✓ Removidos {removed} registros com valores ausentes")
        
        return self.df
    
    def remove_duplicates(self) -> pd.DataFrame:
        """
        Remove registros duplicados
        
        Returns:
            DataFrame sem duplicatas
        """
        if self.df is None:
            raise ValueError("Nenhum dado carregado. Use load_data() primeiro.")
        
        initial_count = len(self.df)
        
        # Remove duplicatas baseado em colunas chave
        self.df = self.df.drop_duplicates(
            subset=['ip', 'timestamp', 'method', 'path', 'status'],
            keep='first'
        )
        
        removed = initial_count - len(self.df)
        if removed > 0:
            print(f"✓ Removidas {removed} linhas duplicadas")
        
        return self.df
    
    def remove_outliers(self, column: str = 'size', threshold: float = 3.0) -> pd.DataFrame:
        """
        Remove outliers usando o método Z-score
        
        Args:
            column: Nome da coluna para detectar outliers
            threshold: Limiar do Z-score (padrão: 3.0)
            
        Returns:
            DataFrame sem outliers
        """
        if self.df is None:
            raise ValueError("Nenhum dado carregado. Use load_data() primeiro.")
        
        if column not in self.df.columns:
            print(f"Aviso: Coluna '{column}' não encontrada")
            return self.df
        
        initial_count = len(self.df)
        
        # Calcula Z-score
        mean = self.df[column].mean()
        std = self.df[column].std()
        
        if std > 0:
            z_scores = np.abs((self.df[column] - mean) / std)
            self.df = self.df[z_scores < threshold]
            
            removed = initial_count - len(self.df)
            if removed > 0:
                print(f"✓ Removidos {removed} outliers da coluna '{column}'")
        
        return self.df
    
    def generate_features(self) -> pd.DataFrame:
        """
        Gera atributos relevantes para análise
        
        Returns:
            DataFrame com novos atributos
        """
        if self.df is None:
            raise ValueError("Nenhum dado carregado. Use load_data() primeiro.")
        
        # 1. Tamanho da requisição (já existe, mas vamos garantir)
        if 'request_size' not in self.df.columns:
            self.df['request_size'] = self.df.apply(
                lambda row: len(str(row['method'])) + len(str(row['path'])), 
                axis=1
            )
        
        # 2. Comprimento do caminho (path)
        self.df['path_length'] = self.df['path'].str.len()
        
        # 3. Número de barras no caminho (profundidade)
        self.df['path_depth'] = self.df['path'].str.count('/')
        
        # 4. Presença de extensão no path
        self.df['has_extension'] = self.df['path'].str.contains(r'\.\w+$', regex=True)
        
        # 5. Tipo de status (sucesso, redirecionamento, erro cliente, erro servidor)
        self.df['status_category'] = self.df['status'].apply(self._categorize_status)
        
        # 6. Tem parâmetros na URL
        self.df['has_params'] = self.df['num_params'] > 0
        
        # 7. Comprimento dos parâmetros
        self.df['params_length'] = self.df['query_params'].str.len()
        
        # 8. Detecta padrões suspeitos simples
        self.df['suspicious_chars'] = self.df['path'].apply(self._detect_suspicious_chars)
        
        print("✓ Atributos gerados com sucesso")
        print(f"  - request_size: Tamanho total da requisição")
        print(f"  - path_length: Comprimento do caminho")
        print(f"  - path_depth: Profundidade do caminho")
        print(f"  - has_extension: Presença de extensão de arquivo")
        print(f"  - status_category: Categoria do status HTTP")
        print(f"  - has_params: Presença de parâmetros na URL")
        print(f"  - params_length: Tamanho dos parâmetros")
        print(f"  - suspicious_chars: Contagem de caracteres suspeitos")
        
        return self.df
    
    def _categorize_status(self, status: int) -> str:
        """
        Categoriza código de status HTTP
        
        Args:
            status: Código de status HTTP
            
        Returns:
            Categoria do status
        """
        if 200 <= status < 300:
            return 'success'
        elif 300 <= status < 400:
            return 'redirect'
        elif 400 <= status < 500:
            return 'client_error'
        elif 500 <= status < 600:
            return 'server_error'
        else:
            return 'unknown'
    
    def _detect_suspicious_chars(self, path: str) -> int:
        """
        Detecta caracteres potencialmente suspeitos no path
        
        Args:
            path: Caminho da URL
            
        Returns:
            Contagem de caracteres suspeitos
        """
        suspicious_patterns = [
            r'\.\.',      # Path traversal
            r'<.*>',      # Possível XSS
            r'script',    # Script tags
            r'union',     # SQL injection
            r'select',    # SQL injection
            r'drop',      # SQL injection
            r'exec',      # Command injection
            r'%',         # URL encoding
            r'\\x',       # Hex encoding
        ]
        
        count = 0
        path_lower = path.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, path_lower):
                count += 1
        
        return count
    
    def clean_all(self) -> pd.DataFrame:
        """
        Executa todas as etapas de limpeza
        
        Returns:
            DataFrame limpo e processado
        """
        print("\n=== Iniciando Pré-processamento ===")
        
        # 1. Remover valores ausentes
        print("\n1. Removendo valores ausentes...")
        self.remove_missing_values(strategy='fill')
        
        # 2. Remover duplicatas
        print("\n2. Removendo duplicatas...")
        self.remove_duplicates()
        
        # 3. Remover outliers
        print("\n3. Removendo outliers...")
        self.remove_outliers(column='size')
        
        # 4. Gerar atributos
        print("\n4. Gerando atributos...")
        self.generate_features()
        
        self.cleaned_df = self.df.copy()
        
        print("\n✓ Pré-processamento concluído!")
        print(f"  Total de registros: {len(self.cleaned_df)}")
        
        return self.cleaned_df
    
    def get_summary(self) -> Dict:
        """
        Retorna resumo dos dados processados
        
        Returns:
            Dicionário com estatísticas resumidas
        """
        if self.cleaned_df is None:
            if self.df is not None:
                df = self.df
            else:
                return {}
        else:
            df = self.cleaned_df
        
        summary = {
            'total_records': len(df),
            'columns': list(df.columns),
            'missing_values': df.isnull().sum().to_dict(),
            'data_types': df.dtypes.astype(str).to_dict(),
            'numeric_summary': df.describe().to_dict() if len(df) > 0 else {}
        }
        
        return summary


def main():
    """
    Função de demonstração
    """
    print("=== Módulo de Pré-processamento ===\n")
    
    # Criar dados de exemplo
    sample_data = pd.DataFrame([
        {'ip': '192.168.1.1', 'method': 'GET', 'path': '/index.html', 
         'status': 200, 'size': 1234, 'query_params': '', 'num_params': 0},
        {'ip': '192.168.1.2', 'method': 'POST', 'path': '/login', 
         'status': 200, 'size': 567, 'query_params': '', 'num_params': 0},
        {'ip': '192.168.1.1', 'method': 'GET', 'path': '/index.html', 
         'status': 200, 'size': 1234, 'query_params': '', 'num_params': 0},  # Duplicata
        {'ip': '10.0.0.1', 'method': 'GET', 'path': '/admin/../etc/passwd', 
         'status': 404, 'size': 178, 'query_params': '', 'num_params': 0},
        {'ip': '172.16.0.1', 'method': 'GET', 'path': '/search', 
         'status': 200, 'size': np.nan, 'query_params': 'q=test', 'num_params': 1},
    ])
    
    # Processar dados
    preprocessor = DataPreprocessor()
    preprocessor.load_data(sample_data)
    cleaned_data = preprocessor.clean_all()
    
    print("\n--- Dados Limpos ---")
    print(cleaned_data)
    
    print("\n--- Resumo ---")
    summary = preprocessor.get_summary()
    print(f"Total de registros: {summary['total_records']}")
    print(f"Colunas: {len(summary['columns'])}")


if __name__ == "__main__":
    main()
