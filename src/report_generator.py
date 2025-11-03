"""
Gerador de Relatórios para o Sistema de Detecção de Ameaças
Responsável por criar relatórios e visualizações dos dados processados
"""

import pandas as pd
import json
from datetime import datetime
from typing import Dict, List, Optional
import os


class ReportGenerator:
    """
    Classe responsável pela geração de relatórios
    """
    
    def __init__(self, data: Optional[pd.DataFrame] = None):
        """
        Inicializa o gerador de relatórios
        
        Args:
            data: DataFrame com os dados processados
        """
        self.data = data
        self.report = {}
        
    def load_data(self, data: pd.DataFrame):
        """
        Carrega dados para geração de relatórios
        
        Args:
            data: DataFrame com os dados
        """
        self.data = data
        
    def generate_summary_report(self) -> Dict:
        """
        Gera relatório resumido dos dados
        
        Returns:
            Dicionário com o relatório
        """
        if self.data is None or len(self.data) == 0:
            return {'error': 'Nenhum dado disponível'}
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_requests': len(self.data),
            'unique_ips': int(self.data['ip'].nunique()),
            'date_range': {
                'start': str(self.data['timestamp'].min()) if 'timestamp' in self.data.columns else 'N/A',
                'end': str(self.data['timestamp'].max()) if 'timestamp' in self.data.columns else 'N/A'
            }
        }
        
        # Estatísticas de requisições
        if 'method' in self.data.columns:
            report['requests_by_method'] = self.data['method'].value_counts().to_dict()
        
        # Estatísticas de status
        if 'status' in self.data.columns:
            report['requests_by_status'] = self.data['status'].value_counts().to_dict()
            
        if 'status_category' in self.data.columns:
            report['requests_by_category'] = self.data['status_category'].value_counts().to_dict()
        
        # Estatísticas de tamanho
        if 'size' in self.data.columns:
            report['data_transfer'] = {
                'total_bytes': int(self.data['size'].sum()),
                'avg_bytes': float(self.data['size'].mean()),
                'max_bytes': int(self.data['size'].max()),
                'min_bytes': int(self.data['size'].min())
            }
        
        # Top IPs
        if 'ip' in self.data.columns:
            top_ips = self.data['ip'].value_counts().head(10)
            report['top_10_ips'] = top_ips.to_dict()
        
        # Top paths
        if 'path' in self.data.columns:
            top_paths = self.data['path'].value_counts().head(10)
            report['top_10_paths'] = top_paths.to_dict()
        
        self.report = report
        return report
    
    def generate_security_report(self) -> Dict:
        """
        Gera relatório focado em segurança
        
        Returns:
            Dicionário com análise de segurança
        """
        if self.data is None or len(self.data) == 0:
            return {'error': 'Nenhum dado disponível'}
        
        security_report = {
            'timestamp': datetime.now().isoformat(),
            'total_requests': len(self.data)
        }
        
        # Requisições com caracteres suspeitos
        if 'suspicious_chars' in self.data.columns:
            suspicious = self.data[self.data['suspicious_chars'] > 0]
            security_report['suspicious_requests'] = {
                'count': len(suspicious),
                'percentage': round(len(suspicious) / len(self.data) * 100, 2)
            }
            
            if len(suspicious) > 0:
                security_report['top_suspicious'] = suspicious.nlargest(5, 'suspicious_chars')[
                    ['ip', 'path', 'status', 'suspicious_chars']
                ].to_dict('records')
        
        # Erros 4xx (possíveis tentativas de acesso não autorizado)
        if 'status' in self.data.columns:
            errors_4xx = self.data[(self.data['status'] >= 400) & (self.data['status'] < 500)]
            security_report['client_errors'] = {
                'count': len(errors_4xx),
                'percentage': round(len(errors_4xx) / len(self.data) * 100, 2)
            }
            
            if len(errors_4xx) > 0:
                # IPs com mais erros 4xx
                top_error_ips = errors_4xx['ip'].value_counts().head(5)
                security_report['top_error_ips'] = top_error_ips.to_dict()
        
        # Requisições com parâmetros (possíveis vetores de ataque)
        if 'has_params' in self.data.columns:
            with_params = self.data[self.data['has_params'] == True]
            security_report['requests_with_params'] = {
                'count': len(with_params),
                'percentage': round(len(with_params) / len(self.data) * 100, 2)
            }
        
        # Paths anormalmente longos
        if 'path_length' in self.data.columns:
            avg_length = self.data['path_length'].mean()
            std_length = self.data['path_length'].std()
            threshold = avg_length + (2 * std_length)
            
            long_paths = self.data[self.data['path_length'] > threshold]
            security_report['abnormally_long_paths'] = {
                'count': len(long_paths),
                'threshold': round(threshold, 2),
                'examples': long_paths.nlargest(3, 'path_length')[
                    ['ip', 'path', 'path_length']
                ].to_dict('records') if len(long_paths) > 0 else []
            }
        
        return security_report
    
    def generate_html_report(self, output_file: str = 'report.html') -> str:
        """
        Gera relatório em HTML
        
        Args:
            output_file: Nome do arquivo de saída
            
        Returns:
            Caminho do arquivo gerado
        """
        summary = self.generate_summary_report()
        security = self.generate_security_report()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - Sistema de Detecção de Ameaças</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        .metric {{
            display: inline-block;
            background-color: #ecf0f1;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 5px;
            min-width: 200px;
        }}
        .metric-label {{
            font-size: 12px;
            color: #7f8c8d;
            text-transform: uppercase;
        }}
        .metric-value {{
            font-size: 28px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .alert {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
        }}
        .danger {{
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 15px 0;
        }}
        .success {{
            background-color: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 15px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Relatório de Segurança - Detecção de Ameaças Cibernéticas</h1>
        <p class="timestamp">Gerado em: {summary.get('timestamp', 'N/A')}</p>
        
        <h2>📊 Resumo Geral</h2>
        <div class="metric">
            <div class="metric-label">Total de Requisições</div>
            <div class="metric-value">{summary.get('total_requests', 0)}</div>
        </div>
        <div class="metric">
            <div class="metric-label">IPs Únicos</div>
            <div class="metric-value">{summary.get('unique_ips', 0)}</div>
        </div>
        
        <h2>🔍 Análise de Segurança</h2>
        
        <div class="danger">
            <strong>⚠️ Requisições Suspeitas:</strong> 
            {security.get('suspicious_requests', {}).get('count', 0)} 
            ({security.get('suspicious_requests', {}).get('percentage', 0)}%)
        </div>
        
        <div class="alert">
            <strong>❌ Erros de Cliente (4xx):</strong> 
            {security.get('client_errors', {}).get('count', 0)} 
            ({security.get('client_errors', {}).get('percentage', 0)}%)
        </div>
        
        <h2>📈 Distribuição de Status</h2>
        <table>
            <tr>
                <th>Código de Status</th>
                <th>Quantidade</th>
            </tr>
"""
        
        # Adicionar status codes
        for status, count in summary.get('requests_by_status', {}).items():
            html_content += f"""
            <tr>
                <td>{status}</td>
                <td>{count}</td>
            </tr>
"""
        
        html_content += """
        </table>
        
        <h2>🌐 Top 10 IPs</h2>
        <table>
            <tr>
                <th>Endereço IP</th>
                <th>Requisições</th>
            </tr>
"""
        
        # Adicionar top IPs
        for ip, count in list(summary.get('top_10_ips', {}).items())[:10]:
            html_content += f"""
            <tr>
                <td>{ip}</td>
                <td>{count}</td>
            </tr>
"""
        
        html_content += """
        </table>
        
        <div class="success">
            <strong>✅ Sistema de Detecção Ativo</strong>
            <p>O sistema está monitorando ativamente todas as requisições e identificando padrões suspeitos.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✓ Relatório HTML gerado: {output_file}")
        return output_file
    
    def generate_json_report(self, output_file: str = 'report.json') -> str:
        """
        Gera relatório em JSON
        
        Args:
            output_file: Nome do arquivo de saída
            
        Returns:
            Caminho do arquivo gerado
        """
        summary = self.generate_summary_report()
        security = self.generate_security_report()
        
        full_report = {
            'summary': summary,
            'security': security
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Relatório JSON gerado: {output_file}")
        return output_file
    
    def print_console_report(self):
        """
        Imprime relatório no console
        """
        summary = self.generate_summary_report()
        security = self.generate_security_report()
        
        print("\n" + "="*70)
        print("🛡️  RELATÓRIO DE SEGURANÇA - DETECÇÃO DE AMEAÇAS CIBERNÉTICAS")
        print("="*70)
        
        print(f"\n📅 Gerado em: {summary.get('timestamp', 'N/A')}")
        
        print("\n📊 RESUMO GERAL")
        print("-" * 70)
        print(f"Total de Requisições: {summary.get('total_requests', 0)}")
        print(f"IPs Únicos: {summary.get('unique_ips', 0)}")
        
        if 'data_transfer' in summary:
            dt = summary['data_transfer']
            print(f"Transferência Total: {dt['total_bytes']:,} bytes")
            print(f"Média por Requisição: {dt['avg_bytes']:.2f} bytes")
        
        print("\n🔍 ANÁLISE DE SEGURANÇA")
        print("-" * 70)
        
        if 'suspicious_requests' in security:
            sr = security['suspicious_requests']
            print(f"⚠️  Requisições Suspeitas: {sr['count']} ({sr['percentage']}%)")
        
        if 'client_errors' in security:
            ce = security['client_errors']
            print(f"❌ Erros de Cliente (4xx): {ce['count']} ({ce['percentage']}%)")
        
        if 'requests_with_params' in security:
            rp = security['requests_with_params']
            print(f"🔗 Requisições com Parâmetros: {rp['count']} ({rp['percentage']}%)")
        
        print("\n🌐 TOP 5 IPs MAIS ATIVOS")
        print("-" * 70)
        for i, (ip, count) in enumerate(list(summary.get('top_10_ips', {}).items())[:5], 1):
            print(f"{i}. {ip}: {count} requisições")
        
        print("\n" + "="*70)


def main():
    """
    Função de demonstração
    """
    print("=== Gerador de Relatórios ===\n")
    
    # Criar dados de exemplo
    sample_data = pd.DataFrame([
        {'ip': '192.168.1.1', 'method': 'GET', 'path': '/index.html', 
         'status': 200, 'size': 1234, 'timestamp': '2025-10-28 10:00:00',
         'suspicious_chars': 0, 'has_params': False, 'path_length': 11},
        {'ip': '192.168.1.2', 'method': 'POST', 'path': '/login', 
         'status': 200, 'size': 567, 'timestamp': '2025-10-28 10:01:00',
         'suspicious_chars': 0, 'has_params': False, 'path_length': 6},
        {'ip': '10.0.0.1', 'method': 'GET', 'path': '/admin/../etc/passwd', 
         'status': 404, 'size': 178, 'timestamp': '2025-10-28 10:02:00',
         'suspicious_chars': 3, 'has_params': False, 'path_length': 20},
        {'ip': '192.168.1.1', 'method': 'GET', 'path': '/search?q=test', 
         'status': 200, 'size': 890, 'timestamp': '2025-10-28 10:03:00',
         'suspicious_chars': 0, 'has_params': True, 'path_length': 14},
    ])
    
    # Gerar relatórios
    generator = ReportGenerator(sample_data)
    
    generator.print_console_report()
    generator.generate_json_report()
    generator.generate_html_report()


if __name__ == "__main__":
    main()
