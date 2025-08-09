#!/usr/bin/env python3
"""
Inspetor de Offsets - Análise detalhada do arquivo após patch
Verifica exatamente o que está nos offsets especificados.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional
import pandas as pd

# Adiciona o diretório raiz ao sys.path
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

logger = setup_logger()

class OffsetInspector:
    """
    Inspector para análise detalhada de offsets no arquivo patcheado.
    """
    
    def __init__(self, output_file: Optional[Path] = None, verbose: bool = True):
        self.original_file = None
        self.patched_file = None
        self.csv_data = None
        self.output_file = output_file
        self.verbose = verbose
        self.report_lines = []
        
        # Configurações de encoding para tentar decodificar
        self.encodings = ['shift_jis', 'ascii', 'latin-1', 'utf-8']
        
        # Padrões conhecidos do jogo
        self.codec_controls = ['#N', '#P', '#W', '#C', '#K', '#E', '#S', '#T']
    
    def log_and_save(self, message: str, level: str = "INFO"):
        """Log tanto no terminal quanto no arquivo de saída."""
        # Adiciona ao relatório
        self.report_lines.append(message)
        
        # Log no terminal se verbose
        if self.verbose:
            if level == "INFO":
                logger.info(message)
            elif level == "WARNING":
                logger.warning(message)
            elif level == "ERROR":
                logger.error(message)
    
    def save_report(self):
        """Salva o relatório completo no arquivo."""
        if not self.output_file:
            return
            
        try:
            # Cria diretório se não existir
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                # Cabeçalho do relatório
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                f.write(f"RELATORIO DE INSPECAO DE OFFSETS - MGS PSX\n")
                f.write(f"Gerado em: {timestamp}\n")
                f.write(f"{'='*80}\n\n")
                
                # Escreve todas as linhas do relatório
                for line in self.report_lines:
                    f.write(line + "\n")
            
            if self.verbose:
                logger.info(f"[FILE] Relatorio salvo em: {self.output_file}")
                
        except Exception as e:
            if self.verbose:
                logger.error(f"[ERROR] Erro ao salvar relatorio: {e}")
    
    def finalize_report(self):
        """Finaliza e salva o relatório."""
        self.save_report()
    
    def load_files(self, original_path: Path, patched_path: Path, csv_path: Optional[Path] = None):
        """Carrega os arquivos para análise."""
        
        logger.info(f"Carregando arquivos para inspeção...")
        
        # Carrega arquivo original
        try:
            with open(original_path, 'rb') as f:
                self.original_file = f.read()
            logger.info(f" Original carregado: {len(self.original_file)} bytes")
        except Exception as e:
            logger.error(f" Erro ao carregar original: {e}")
            return False
        
        # Carrega arquivo patcheado
        try:
            with open(patched_path, 'rb') as f:
                self.patched_file = f.read()
            logger.info(f" Patcheado carregado: {len(self.patched_file)} bytes")
        except Exception as e:
            logger.error(f" Erro ao carregar patcheado: {e}")
            return False
        
        # Carrega CSV se fornecido
        if csv_path and csv_path.exists():
            try:
                self.csv_data = pd.read_csv(csv_path, delimiter="\t")
                logger.info(f" CSV carregado: {len(self.csv_data)} entradas")
            except Exception as e:
                logger.warning(f" Erro ao carregar CSV: {e}")
        
        # Verifica integridade
        if len(self.original_file) != len(self.patched_file):
            logger.error(f" Tamanhos diferentes! Original: {len(self.original_file)}, Patch: {len(self.patched_file)}")
            return False
        
        return True
    
    def find_csv_info(self, offset: int) -> Optional[Dict]:
        """Encontra informações do CSV para o offset especificado."""
        
        if self.csv_data is None:
            return None
        
        try:
            # Procura pelo offset (tanto hex quanto int)
            hex_offset = f"0x{offset:x}"
            
            mask1 = self.csv_data['offset'] == hex_offset
            mask2 = self.csv_data['offset'] == hex_offset.upper()
            
            matches = self.csv_data[mask1 | mask2]
            
            if len(matches) > 0:
                row = matches.iloc[0]
                return {
                    'original_text': str(row.get('texto', 'N/A')),
                    'translated_text': str(row.get('texto_traduzido', 'N/A')),
                    'encoding': str(row.get('encoding', 'N/A')),
                    'size': str(row.get('size', 'N/A'))
                }
        except Exception as e:
            if self.verbose:
                logger.warning(f"Erro ao buscar no CSV: {e}")
        
        return None
    
    def analyze_critical_pattern(self, data: bytes) -> Dict:
        """Analisa padrões críticos nos dados."""
        
        analysis = {
            'has_00_ff': False,
            'ff_positions': [],
            'null_positions': [],
            'control_bytes': [],
            'possible_terminators': []
        }
        
        # Busca padrão 00 FF
        pos = 0
        while True:
            pos = data.find(b'\x00\xff', pos)
            if pos == -1:
                break
            analysis['ff_positions'].append(pos)
            analysis['has_00_ff'] = True
            pos += 1
        
        # Busca nulls isolados
        for i, byte in enumerate(data):
            if byte == 0x00:
                analysis['null_positions'].append(i)
            elif byte < 32 and byte not in [0x0A, 0x0D]:  # Possíveis bytes de controle
                analysis['control_bytes'].append((i, byte))
        
        # Analisa possíveis terminadores
        for i in range(len(data) - 3):
            chunk = data[i:i+4]
            if b'\x00' in chunk or b'\xff' in chunk:
                analysis['possible_terminators'].append((i, chunk.hex()))
        
        return analysis
    
    def decode_data(self, data: bytes, max_length: int = 200) -> Dict[str, str]:
        """Tenta decodificar os dados em diferentes encodings."""
        
        results = {}
        
        for encoding in self.encodings:
            try:
                decoded = data.decode(encoding, errors='ignore')
                # Limita o tamanho e remove caracteres de controle problemáticos
                clean_decoded = ''.join(
                    c if ord(c) >= 32 or c in ['\n', '\t'] 
                    else f'\\x{ord(c):02x}' 
                    for c in decoded[:max_length]
                )
                results[encoding] = clean_decoded
            except Exception as e:
                results[encoding] = f"ERRO: {str(e)}"
        
        return results
    
    def analyze_critical_pattern(self, data: bytes) -> Dict:
        """Analisa padrões críticos nos dados."""
        
        analysis = {
            'has_00_ff': False,
            'ff_positions': [],
            'null_positions': [],
            'control_bytes': [],
            'possible_terminators': []
        }
        
        # Busca padrão 00 FF
        pos = 0
        while True:
            pos = data.find(b'\x00\xff', pos)
            if pos == -1:
                break
            analysis['ff_positions'].append(pos)
            analysis['has_00_ff'] = True
            pos += 1
        
        # Busca nulls isolados
        for i, byte in enumerate(data):
            if byte == 0x00:
                analysis['null_positions'].append(i)
            elif byte < 32 and byte not in [0x0A, 0x0D]:  # Possíveis bytes de controle
                analysis['control_bytes'].append((i, byte))
        
        # Analisa possíveis terminadores
        for i in range(len(data) - 3):
            chunk = data[i:i+4]
            if b'\x00' in chunk or b'\xff' in chunk:
                analysis['possible_terminators'].append((i, chunk.hex()))
        
        return analysis
    
    def inspect_offset(self, offset: int, context_size: int = 150) -> Dict:
        """Inspects a specific offset in detail."""
        
        logger.info(f"\n{'='*60}")
        logger.info(f" INSPECIONANDO OFFSET: {hex(offset)}")
        logger.info(f"{'='*60}")
        
        result = {
            'offset': offset,
            'hex_offset': hex(offset),
            'status': 'unknown',
            'csv_info': None,
            'original_data': None,
            'patched_data': None,
            'comparison': None,
            'analysis': None
        }
        
        # Verifica bounds
        if offset >= len(self.original_file):
            result['status'] = 'offset_out_of_bounds'
            logger.error(f" Offset fora dos limites: {hex(offset)} >= {hex(len(self.original_file))}")
            return result
        
        # Busca informações do CSV
        csv_info = self.find_csv_info(offset)
        result['csv_info'] = csv_info
        
        if csv_info:
            logger.info(f" INFORMAÇÕES DO CSV:")
            logger.info(f"   Original: '{csv_info['original_text'][:80]}{'...' if len(csv_info['original_text']) > 80 else ''}'")
            logger.info(f"   Traduzido: '{csv_info['translated_text'][:80]}{'...' if len(csv_info['translated_text']) > 80 else ''}'")
            logger.info(f"   Encoding: {csv_info['encoding']}")
            logger.info(f"   Size: {csv_info['size']}")
        else:
            logger.warning(f" Offset não encontrado no CSV")
        
        # Extrai contexto dos arquivos
        start = max(0, offset - context_size // 2)
        end = min(len(self.original_file), offset + context_size // 2)
        
        original_context = self.original_file[start:end]
        patched_context = self.patched_file[start:end]
        
        # Dados específicos do offset
        data_size = min(100, len(self.original_file) - offset)
        original_data = self.original_file[offset:offset + data_size]
        patched_data = self.patched_file[offset:offset + data_size]
        
        result['original_data'] = original_data
        result['patched_data'] = patched_data
        
        # Comparação
        is_different = original_data != patched_data
        result['comparison'] = {
            'is_different': is_different,
            'different_bytes': sum(1 for a, b in zip(original_data, patched_data) if a != b),
            'total_bytes': len(original_data)
        }
        
        logger.info(f" COMPARAÇÃO ORIGINAL vs PATCHEADO:")
        logger.info(f"   Dados diferentes: {'SIM' if is_different else 'NAO'}")
        if is_different:
            logger.info(f"   Bytes diferentes: {result['comparison']['different_bytes']}/{result['comparison']['total_bytes']}")
            result['status'] = 'modified'
        else:
            logger.info(f"    DADOS IDÊNTICOS - Patch não foi aplicado!")
            result['status'] = 'not_modified'
        
        # Análise detalhada dos dados
        logger.info(f" DADOS ORIGINAIS:")
        logger.info(f"   Hex: {original_data[:50].hex()}{'...' if len(original_data) > 50 else ''}")
        
        original_decoded = self.decode_data(original_data)
        for encoding, text in original_decoded.items():
            if text and not text.startswith('ERRO'):
                logger.info(f"   {encoding}: '{text[:80]}{'...' if len(text) > 80 else ''}'")
                break
        
        logger.info(f" DADOS PATCHEADOS:")
        logger.info(f"   Hex: {patched_data[:50].hex()}{'...' if len(patched_data) > 50 else ''}")
        
        patched_decoded = self.decode_data(patched_data)
        for encoding, text in patched_decoded.items():
            if text and not text.startswith('ERRO'):
                logger.info(f"   {encoding}: '{text[:80]}{'...' if len(text) > 80 else ''}'")
                break
        
        # Análise de padrões críticos
        original_analysis = self.analyze_critical_pattern(original_context)
        patched_analysis = self.analyze_critical_pattern(patched_context)
        
        result['analysis'] = {
            'original': original_analysis,
            'patched': patched_analysis
        }
        
        logger.info(f" ANÁLISE DE PADRÕES CRÍTICOS:")
        logger.info(f"   Original - Padrão 00 FF: {'SIM' if original_analysis['has_00_ff'] else 'NAO'}")
        logger.info(f"   Patcheado - Padrão 00 FF: {'SIM' if patched_analysis['has_00_ff'] else 'NAO'}")
        
        if original_analysis['has_00_ff']:
            logger.info(f"   Posições FF original: {original_analysis['ff_positions']}")
        if patched_analysis['has_00_ff']:
            logger.info(f"   Posições FF patcheado: {patched_analysis['ff_positions']}")
        
        # Contexto hex para debug
        logger.info(f" CONTEXTO HEX (offset destacado):")
        offset_in_context = offset - start
        
        for i in range(0, min(len(original_context), 128), 16):
            chunk = original_context[i:i+16]
            addr = start + i
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            marker = " <-- TARGET" if start + i <= offset < start + i + 16 else ""
            logger.info(f"   {addr:08x}: {hex_part:<48} |{ascii_part}|{marker}")
        
        return result
    
    def inspect_multiple_offsets(self, offsets: List[str], context_size: int = 150):
        """Inspects multiple offsets and generates a summary report."""
        
        logger.info(f"\n INICIANDO INSPEÇÃO DE {len(offsets)} OFFSETS")
        logger.info(f"{'='*80}")
        
        results = []
        summary = {
            'total': len(offsets),
            'modified': 0,
            'not_modified': 0,
            'out_of_bounds': 0,
            'with_csv_info': 0
        }
        
        for offset_str in offsets:
            try:
                # Converte offset string para int
                if offset_str.startswith('0x'):
                    offset = int(offset_str, 16)
                else:
                    offset = int(offset_str, 16)  # Assume hex se não tem prefixo
                
                result = self.inspect_offset(offset, context_size)
                results.append(result)
                
                # Atualiza estatísticas
                summary[result['status']] += 1
                if result['csv_info']:
                    summary['with_csv_info'] += 1
                    
            except ValueError as e:
                logger.error(f" Offset inválido '{offset_str}': {e}")
                continue
            except Exception as e:
                logger.error(f" Erro ao processar offset '{offset_str}': {e}")
                continue
        
        # Relatório final
        logger.info(f" RELATÓRIO FINAL DA INSPEÇÃO")
        logger.info(f"{'='*50}")
        logger.info(f"Total de offsets analisados: {summary['total']}")
        logger.info(f"Modificados (patch aplicado): {summary['modified']}")
        logger.info(f"Não modificados (patch NÃO aplicado): {summary['not_modified']}")
        logger.info(f"Fora dos limites: {summary['out_of_bounds']}")
        logger.info(f"Com informações no CSV: {summary['with_csv_info']}")
        
        if summary['not_modified'] > 0:
            logger.warning(f" ATENÇÃO: {summary['not_modified']} offsets NÃO foram modificados!")
            logger.warning(f"Isso indica que o patch não foi aplicado nesses locais.")
        
        if summary['modified'] > 0:
            logger.info(f" {summary['modified']} offsets foram modificados com sucesso.")
        
        return results, summary


def main():
    """Função principal do inspetor."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Inspetor de Offsets - Análise detalhada pós-patch")
    parser.add_argument("--original", type=Path, 
                       default=BASE_DIR / "assets" / "fontes" / "CD1" / "RADIO.DAT",
                       help="Arquivo original")
    parser.add_argument("--patched", type=Path,
                       default=BASE_DIR / "patches" / "RADIO_PATCHED.DAT", 
                       help="Arquivo patcheado")
    parser.add_argument("--csv", type=Path,
                       default=BASE_DIR / "translated" / "strings_RADIO_traduzido.csv",
                       help="Arquivo CSV com traduções")
    parser.add_argument("--offsets", nargs="+", required=True,
                       help="Lista de offsets para inspecionar (ex: 0x114a01 0x123456)")
    parser.add_argument("--context", type=int, default=150,
                       help="Tamanho do contexto para análise (default: 150)")
    
    args = parser.parse_args()
    
    # Valida arquivos
    if not args.original.exists():
        logger.error(f"Arquivo original não encontrado: {args.original}")
        sys.exit(1)
    
    if not args.patched.exists():
        logger.error(f"Arquivo patcheado não encontrado: {args.patched}")
        sys.exit(1)
    
    # Cria e executa o inspetor
    inspector = OffsetInspector()
    
    if not inspector.load_files(args.original, args.patched, args.csv):
        logger.error("Falha ao carregar arquivos!")
        sys.exit(1)
    
    # Executa inspeção
    results, summary = inspector.inspect_multiple_offsets(args.offsets, args.context)
    
    logger.info(f" INSPEÇÃO CONCLUÍDA!")
    logger.info(f"Use as informações acima para diagnosticar problemas de patch.")


if __name__ == "__main__":
    
    """
    Uso:
        python .\tools\offset_analizer.py --offsets 0x114569 0x1145f1 0x114687 0x1146d5 0x11473f 0x1147cf 0x114889 0x1148cf 0x11491b 0x114978 0x114a01 0x114b24
    """
    
    main()