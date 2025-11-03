"""
Sistema de Coleta de Logs de Servidor Web
Responsável por coletar e processar logs de acesso do servidor
"""

import re
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional
import os


class LogScanner:
    """
    Classe responsável pela coleta e parse de logs de servidor web
    """
    
    def __init__(self, log_file_path: Optional[str] = None):
        """
        Inicializa o scanner de logs
        
        Args:
            log_file_path: Caminho para o arquivo de log (opcional)
        """
        self.log_file_path = log_file_path
        self.logs_data = []
        
        # Padrão regex para Apache/Nginx Combined Log Format
        # Exemplo: 127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
        self.log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) '
            r'- - '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) (?P<protocol>[^"]+)" '
            r'(?P<status>\d+) '
            r'(?P<size>\d+|-)'
        )
    
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """
        Faz o parse de uma linha de log
        
        Args:
            line: Linha do log a ser processada
            
        Returns:
            Dicionário com os dados extraídos ou None se falhar
        """
        match = self.log_pattern.match(line.strip())
        
        if match:
            data = match.groupdict()
            
            # Converte o tamanho para int (trata '-' como 0)
            size = data.get('size', '0')
            data['size'] = int(size) if size.isdigit() else 0
            
            # Converte status para int
            data['status'] = int(data['status'])
            
            # Extrai parâmetros da URL
            path = data.get('path', '')
            if '?' in path:
                base_path, params = path.split('?', 1)
                data['path'] = base_path
                data['query_params'] = params
                data['num_params'] = len(params.split('&'))
            else:
                data['query_params'] = ''
                data['num_params'] = 0
            
            # Calcula tamanho da requisição (URL + método)
            data['request_size'] = len(data['method']) + len(path)
            
            return data
        
        return None
    
    def collect_logs_from_file(self, file_path: Optional[str] = None) -> List[Dict]:
        """
        Coleta logs de um arquivo
        
        Args:
            file_path: Caminho do arquivo de log
            
        Returns:
            Lista de dicionários com os dados coletados
        """
        if file_path:
            self.log_file_path = file_path
        
        if not self.log_file_path or not os.path.exists(self.log_file_path):
            print(f"Arquivo de log não encontrado: {self.log_file_path}")
            return []
        
        self.logs_data = []
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    parsed = self.parse_log_line(line)
                    if parsed:
                        parsed['line_number'] = line_num
                        self.logs_data.append(parsed)
                    else:
                        print(f"Aviso: Linha {line_num} não pôde ser processada")
            
            print(f"Coletados {len(self.logs_data)} registros de log")
            
        except Exception as e:
            print(f"Erro ao ler arquivo de log: {e}")
            return []
        
        return self.logs_data
    
    def collect_logs_from_text(self, log_text: str) -> List[Dict]:
        """
        Coleta logs de uma string de texto
        
        Args:
            log_text: Texto contendo os logs
            
        Returns:
            Lista de dicionários com os dados coletados
        """
        self.logs_data = []
        
        for line_num, line in enumerate(log_text.split('\n'), 1):
            if line.strip():
                parsed = self.parse_log_line(line)
                if parsed:
                    parsed['line_number'] = line_num
                    self.logs_data.append(parsed)
        
        print(f" Coletados {len(self.logs_data)} registros de log")
        return self.logs_data
    
    def get_dataframe(self) -> pd.DataFrame:
        """
        Retorna os dados coletados como DataFrame do pandas
        
        Returns:
            DataFrame com os logs coletados
        """
        if not self.logs_data:
            print("Nenhum dado coletado ainda")
            return pd.DataFrame()
        
        return pd.DataFrame(self.logs_data)
    
    def get_statistics(self) -> Dict:
        """
        Retorna estatísticas básicas dos logs coletados
        
        Returns:
            Dicionário com estatísticas
        """
        if not self.logs_data:
            return {}
        
        df = self.get_dataframe()
        
        stats = {
            'total_requests': len(df),
            'unique_ips': df['ip'].nunique(),
            'unique_paths': df['path'].nunique(),
            'status_codes': df['status'].value_counts().to_dict(),
            'total_bytes': df['size'].sum(),
            'avg_request_size': df['request_size'].mean(),
            'methods': df['method'].value_counts().to_dict()
        }
        
        return stats


def main():
    """
    Função principal para demonstração
    """
    print("=== Sistema de Coleta de Logs - Detecção de Ameaças Cibernéticas ===\n")
    
    # Criar scanner
    scanner = LogScanner()
    
    # Verificar se existe arquivo de log
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        print("Uso: python scanner.py <arquivo_de_log>")
        print("\nExemplo de formato de log esperado:")
        print('  192.168.1.100 - - [28/Oct/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234')
        print("\nFormato: Apache/Nginx Combined Log Format")
        return
    
    # Coletar logs
    print(f"\n--- Coletando logs de: {log_file} ---")
    scanner.collect_logs_from_file(log_file)
    
    if not scanner.logs_data:
        print("Nenhum log foi coletado. Verifique o formato do arquivo.")
        return
    
    # Exibir estatísticas
    print("\n--- Estatísticas dos Logs ---")
    stats = scanner.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    # Exibir DataFrame
    print("\n--- Dados Coletados (primeiras 5 linhas) ---")
    df = scanner.get_dataframe()
    print(df.head())
    
    # Salvar em CSV
    output_file = 'collected_logs.csv'
    df.to_csv(output_file, index=False)
    print(f"\n✓ Dados salvos em '{output_file}'")


if __name__ == "__main__":
    main()
