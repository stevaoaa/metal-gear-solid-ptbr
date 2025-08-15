#!/usr/bin/env python3
"""
Inspetor de Offsets - Análise detalhada do arquivo após patch
Verifica exatamente o que está nos offsets especificados.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional
import pandas as pd
import argparse

# Adiciona o diretório raiz ao sys.path
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

logger = setup_logger()

# Mapeamento de arquivos disponíveis por CD (mesmo dos outros scripts)
FILE_MAPPING = {
    "CD1": {
        # arquivos do CD1
        "radio": "RADIO.DAT",
        "stage": "STAGE.DIR",
        "demo": "DEMO.DAT",
        "vox": "VOX.DAT",
        "zmovie": "ZMOVIE.STR"
    },
    "CD2": {
        # arquivos do CD2
        "radio": "RADIO.DAT",
        "stage": "STAGE.DIR",
        "demo": "DEMO.DAT",
        "vox": "VOX.DAT",
        "zmovie": "ZMOVIE.STR"
    }
}

class FileResolver:
    """Resolve arquivos baseado em parâmetros intuitivos."""
    
    def __init__(self, cd: str = "CD1"):
        self.cd = cd
        self.assets_path = BASE_DIR / "assets" / "fontes" / cd
        self.patches_path = BASE_DIR / "patches"
        self.extracted_path = BASE_DIR / "extracted"
        self.translated_path = BASE_DIR / "translated"
    
    def get_available_files(self) -> Dict[str, str]:
        """Retorna os arquivos disponíveis para o CD atual."""
        return FILE_MAPPING.get(self.cd, {})
    
    def get_original_path(self, file_key: str) -> Optional[Path]:
        """Retorna o caminho do arquivo original."""
        available_files = self.get_available_files()
        if file_key in available_files:
            file_path = self.assets_path / available_files[file_key]
            return file_path if file_path.exists() else None
        return None
    
    def get_patched_path(self, file_key: str) -> Optional[Path]:
        """Retorna o caminho do arquivo patcheado."""
        available_files = self.get_available_files()
        if file_key in available_files:
            filename = available_files[file_key]
            base_name = Path(filename).stem
            
            # Tenta diferentes nomes de arquivo patcheado
            possible_names = [
                f"{base_name}_PATCHED.DAT",
                f"{base_name}_patched.dat",
                f"{base_name}_PATCHED.DIR",
                f"{base_name}_patched.dir",
                f"{base_name}_PATCHED.STR",
                f"{base_name}_patched.str", 
                f"{filename}_patched",
                f"patched_{filename}",
                filename  # Fallback para o mesmo nome
            ]
            
            for name in possible_names:
                patched_path = self.patches_path / name
                if patched_path.exists():
                    return patched_path
        
        return None
    
    def get_csv_path(self, file_key: str, prefer_translated: bool = True) -> Optional[Path]:
        """Encontra o CSV correspondente ao arquivo."""
        available_files = self.get_available_files()
        if file_key not in available_files:
            return None
        
        filename = available_files[file_key]
        base_name = Path(filename).stem
        
        # Tenta encontrar arquivo traduzido primeiro
        if prefer_translated:
            translated_csv = self.translated_path / f"strings_{base_name}_traduzido.csv"
            if translated_csv.exists():
                return translated_csv
        
        # Fallback para arquivo extraído
        extracted_csv = self.extracted_path / f"strings_{base_name}.csv"
        if extracted_csv.exists():
            return extracted_csv
        
        return None
    
    def list_available_files(self) -> List[str]:
        """Lista todos os arquivos disponíveis no diretório do CD."""
        if not self.assets_path.exists():
            return []
        
        available_files = []
        file_mapping = self.get_available_files()
        
        for key, filename in file_mapping.items():
            original_path = self.get_original_path(key)
            patched_path = self.get_patched_path(key)
            csv_path = self.get_csv_path(key)
            
            original_status = "✓" if original_path else "✗"
            patched_status = "✓" if patched_path else "✗"
            csv_status = "✓" if csv_path else "✗"
            
            size = ""
            if original_path:
                size_bytes = original_path.stat().st_size
                if size_bytes > 1024*1024:
                    size = f"({size_bytes // (1024*1024)} MB)"
                else:
                    size = f"({size_bytes // 1024} KB)"
            
            patched_info = ""
            if patched_path:
                patched_info = f"Patch: {patched_path.name}"
            
            csv_info = ""
            if csv_path:
                csv_info = f"CSV: {csv_path.name}"
            
            status_info = f"Orig:{original_status} Patch:{patched_status} CSV:{csv_status}"
            available_files.append(f"--{key:<8} {filename:<15} {size:<8} {status_info}")
            
            if patched_info:
                available_files.append(f"{'':>10} {patched_info}")
            if csv_info:
                available_files.append(f"{'':>10} {csv_info}")
            available_files.append("")  # Linha em branco para separar
        
        return available_files


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
            logger.info(f" Original carregado: {original_path.name} ({len(self.original_file)} bytes)")
        except Exception as e:
            logger.error(f" Erro ao carregar original: {e}")
            return False
        
        # Carrega arquivo patcheado
        try:
            with open(patched_path, 'rb') as f:
                self.patched_file = f.read()
            logger.info(f" Patcheado carregado: {patched_path.name} ({len(self.patched_file)} bytes)")
        except Exception as e:
            logger.error(f" Erro ao carregar patcheado: {e}")
            return False
        
        # Carrega CSV se fornecido
        if csv_path and csv_path.exists():
            try:
                # Tenta diferentes delimitadores
                for delimiter in ['\t', ',', ';']:
                    try:
                        self.csv_data = pd.read_csv(csv_path, delimiter=delimiter)
                        if len(self.csv_data.columns) > 1:  # Se tem mais de uma coluna, provavelmente é o delimiter correto
                            break
                    except:
                        continue
                
                logger.info(f" CSV carregado: {csv_path.name} ({len(self.csv_data)} entradas)")
            except Exception as e:
                logger.warning(f" Erro ao carregar CSV: {e}")
        elif csv_path:
            logger.warning(f" CSV não encontrado: {csv_path}")
        
        # Verifica integridade
        if len(self.original_file) != len(self.patched_file):
            logger.warning(f" Tamanhos diferentes! Original: {len(self.original_file)}, Patch: {len(self.patched_file)}")
            # Não retorna False, pois pode ser normal em alguns casos
        
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
                    'size': str(row.get('tamanho_bytes', row.get('size', 'N/A')))
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


def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Inspetor de Offsets - Análise detalhada pós-patch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --demo --offsets 0x114a01 0x123456        # Analisa offsets no DEMO.DAT
  %(prog)s --vox --offsets 0x2f19244 --context 200   # Analisa VOX.DAT com contexto maior
  %(prog)s --cd CD2 --radio --offsets 0x1000         # Analisa RADIO.DAT do CD2
  %(prog)s --list                                     # Lista arquivos disponíveis
  %(prog)s --brf --offsets 0x500 0x600 0x700         # Múltiplos offsets no BRF.DAT
        """
    )
    
    # Grupo para seleção de CD
    cd_group = parser.add_argument_group('Seleção de CD')
    cd_group.add_argument(
        "--cd", 
        choices=list(FILE_MAPPING.keys()),
        default="CD1",
        help="CD para processar (padrão: CD1)"
    )
    
    # Grupo para seleção de arquivo
    file_group = parser.add_argument_group('Seleção de arquivo')
    file_group.add_argument(
        "--list", 
        action="store_true",
        help="Lista arquivos disponíveis e sai"
    )
    
    # Coleta todos os tipos de arquivo únicos de todos os CDs
    all_file_types = set()
    file_descriptions = {}
    
    for cd, files in FILE_MAPPING.items():
        for key, filename in files.items():
            all_file_types.add(key)
            if key not in file_descriptions:
                file_descriptions[key] = filename
    
    # Adiciona argumentos para cada tipo de arquivo único
    for file_key in sorted(all_file_types):
        file_group.add_argument(
            f"--{file_key}", 
            action="store_true",
            help=f"Analisa {file_descriptions[file_key]}"
        )
    
    # Argumentos para compatibilidade com versão anterior
    compat_group = parser.add_argument_group('Compatibilidade (argumentos antigos)')
    compat_group.add_argument(
        "--original", 
        type=Path,
        help="Caminho específico do arquivo original (compatibilidade)"
    )
    compat_group.add_argument(
        "--patched", 
        type=Path,
        help="Caminho específico do arquivo patcheado (compatibilidade)"
    )
    compat_group.add_argument(
        "--csv", 
        type=Path,
        help="Caminho específico do CSV (compatibilidade)"
    )
    
    # Configurações de análise
    analysis_group = parser.add_argument_group('Configurações de análise')
    analysis_group.add_argument(
        "--offsets", 
        nargs="+",
        help="Lista de offsets para inspecionar (ex: 0x114a01 0x123456)"
    )
    analysis_group.add_argument(
        "--context", 
        type=int, 
        default=150,
        help="Tamanho do contexto para análise (default: 150)"
    )
    
    # Outras opções
    other_group = parser.add_argument_group('Outras opções')
    other_group.add_argument(
        "--verbose", "-v", 
        action="store_true",
        default=True,
        help="Saída detalhada (padrão: habilitado)"
    )
    
    return parser


def main():
    """Função principal do inspetor."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Resolver arquivos
    file_resolver = FileResolver(args.cd)
    
    # Lista arquivos e sai se solicitado
    if args.list:
        print(f"\n Arquivos disponíveis em {args.cd}:")
        print("-" * 80)
        available = file_resolver.list_available_files()
        if available:
            for line in available:
                print(f"  {line}")
        else:
            print(f"   Diretório {args.cd} não encontrado")
        print(f"\nUso: {parser.prog} --cd {args.cd} --<arquivo> --offsets <offset1> <offset2>")
        print(f"Exemplo: {parser.prog} --cd {args.cd} --demo --offsets 0x114a01 0x123456")
        return
    
    # Valida se --offsets foi fornecido (obrigatório exceto para --list)
    if not args.offsets:
        logger.error("Argumento --offsets é obrigatório")
        parser.print_help()
        return
    
    # Determina arquivos para análise
    original_file = None
    patched_file = None
    csv_file = None
    
    if args.original and args.patched:
        # Compatibilidade: usa arquivos especificados
        original_file = args.original
        patched_file = args.patched
        csv_file = args.csv
        logger.info("Usando argumentos de compatibilidade")
    else:
        # Usa novo sistema: verifica qual arquivo foi selecionado
        selected_files = []
        available_files = file_resolver.get_available_files()
        
        for key in available_files.keys():
            if getattr(args, key, False):
                selected_files.append(key)
        
        if len(selected_files) == 0:
            logger.error("Nenhum arquivo selecionado!")
            logger.info(f"Use --list para ver arquivos disponíveis ou especifique um arquivo com --demo, --vox, etc.")
            return
        elif len(selected_files) > 1:
            logger.error(f"Múltiplos arquivos selecionados: {', '.join(selected_files)}")
            logger.info("Selecione apenas um arquivo por vez para análise")
            return
        
        # Resolve arquivo selecionado
        file_key = selected_files[0]
        original_file = file_resolver.get_original_path(file_key)
        patched_file = file_resolver.get_patched_path(file_key)
        csv_file = file_resolver.get_csv_path(file_key)
        
        if not original_file:
            logger.error(f"Arquivo original não encontrado: {file_key} ({args.cd})")
            return
        
        if not patched_file:
            logger.error(f"Arquivo patcheado não encontrado: {file_key} ({args.cd})")
            logger.info(f"Procurei em: {file_resolver.patches_path}")
            return
        
        logger.info(f" Arquivo selecionado: {file_key}")
        logger.info(f"   Original: {original_file.name}")
        logger.info(f"   Patcheado: {patched_file.name}")
        if csv_file:
            logger.info(f"   CSV: {csv_file.name}")
        else:
            logger.info(f"   CSV: Não encontrado")
    
    # Valida arquivos
    if not original_file or not original_file.exists():
        logger.error(f"Arquivo original não encontrado: {original_file}")
        return
    
    if not patched_file or not patched_file.exists():
        logger.error(f"Arquivo patcheado não encontrado: {patched_file}")
        return
    
    # Cria e executa o inspetor
    inspector = OffsetInspector(verbose=getattr(args, 'verbose', True))
    
    if not inspector.load_files(original_file, patched_file, csv_file):
        logger.error("Falha ao carregar arquivos!")
        return
    
    # Executa inspeção
    results, summary = inspector.inspect_multiple_offsets(args.offsets, args.context)
    
    logger.info(f"\n INSPEÇÃO CONCLUÍDA!")
    logger.info(f"Use as informações acima para diagnosticar problemas de patch.")


if __name__ == "__main__":
    """
    Exemplos de uso melhorados:
    
    # Analisa offsets no DEMO.DAT do CD1
    python tools/offset_analyzer.py --demo --offsets 0x114a01 0x123456
    
    # Analisa VOX.DAT com contexto maior
    python tools/offset_analyzer.py --vox --offsets 0x2f19244 --context 200
    
    # Analisa RADIO.DAT do CD2 (quando disponível)  
    python tools/offset_analyzer.py --cd CD2 --radio --offsets 0x1000
    
    # Lista arquivos disponíveis
    python tools/offset_analyzer.py --list
    
    # Múltiplos offsets no BRF.DAT
    python tools/offset_analyzer.py --brf --offsets 0x500 0x600 0x700
    
    # Compatibilidade com versão anterior
    python tools/offset_analyzer.py --original arquivo.dat --patched arquivo_patched.dat --offsets 0x1000
    """
    
    main()