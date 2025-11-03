"""
Sistema de Detecção de Ameaças Cibernéticas em Servidores Web
"""

__version__ = '1.0.0'
__author__ = 'Tech Hack - 7º Semestre'

from .scanner import LogScanner
from .report_generator import ReportGenerator

__all__ = ['LogScanner', 'ReportGenerator']
