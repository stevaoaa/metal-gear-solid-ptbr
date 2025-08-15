#!/usr/bin/env python3
"""
Text to Offset Finder - Busca offsets baseado em texto
Encontra onde um texto específico está localizado no arquivo de assets.
"""

import sys
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
import pandas as pd
import argparse

# Adiciona o diretório raiz ao sys.path
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

logger = setup_logger()

# Mapeamento de arquivos disponíveis por CD (mesmo do scan_texts.py)
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
        self.base_path = BASE_DIR / "assets" / "fontes" / cd
        self.extracted_path = BASE_DIR / "extracted"
        self.translated_path = BASE_DIR / "translated"
    
    def get_available_files(self) -> Dict[str, str]:
        """Retorna os arquivos disponíveis para o CD atual."""
        return FILE_MAPPING.get(self.cd, {})
    
    def get_file_path(self, file_key: str) -> Optional[Path]:
        """Converte uma chave de arquivo para o caminho completo."""
        available_files = self.get_available_files()
        if file_key in available_files:
            file_path = self.base_path / available_files[file_key]
            return file_path if file_path.exists() else None
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
        if not self.base_path.exists():
            return []
        
        available_files = []
        file_mapping = self.get_available_files()
        
        for key, filename in file_mapping.items():
            file_path = self.base_path / filename
            csv_path = self.get_csv_path(key)
            
            status = "✓" if file_path.exists() else "✗"
            csv_status = "✓" if csv_path else "✗"
            
            size = ""
            if file_path.exists():
                size_bytes = file_path.stat().st_size
                if size_bytes > 1024*1024:
                    size = f"({size_bytes // (1024*1024)} MB)"
                else:
                    size = f"({size_bytes // 1024} KB)"
            
            csv_info = f"CSV:{csv_status}"
            if csv_path:
                csv_info += f" ({csv_path.name})"
            
            available_files.append(f"{status} --{key:<8} {filename:<15} {size:<8} {csv_info}")
        
        return available_files


class TextOffsetFinder:
    """
    Finder para localizar offsets baseado em texto informado.
    """
    
    def __init__(self, output_file: Optional[Path] = None, verbose: bool = True):
        self.target_file = None
        self.csv_data = None
        self.output_file = output_file
        self.verbose = verbose
        self.report_lines = []
        
        # Configurações de encoding para busca
        self.encodings = ['shift_jis', 'ascii', 'latin-1', 'utf-8']
        
        # Padrões conhecidos do jogo
        self.codec_controls = ['#N', '#P', '#W', '#C', '#K', '#E', '#S', '#T']
    
    def log_and_save(self, message: str, level: str = "INFO"):
        """Log tanto no terminal quanto no arquivo de saída."""
        self.report_lines.append(message)
        
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
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                f.write(f"RELATORIO DE BUSCA DE TEXTO PARA OFFSET - MGS PSX\n")
                f.write(f"Gerado em: {timestamp}\n")
                f.write(f"{'='*80}\n\n")
                
                for line in self.report_lines:
                    f.write(line + "\n")
            
            if self.verbose:
                logger.info(f"[FILE] Relatorio salvo em: {self.output_file}")
                
        except Exception as e:
            if self.verbose:
                logger.error(f"[ERROR] Erro ao salvar relatorio: {e}")
    
    def load_file(self, file_path: Path, csv_path: Optional[Path] = None):
        """Carrega o arquivo para busca."""
        
        logger.info(f"Carregando arquivo para busca de texto...")
        
        # Carrega arquivo principal
        try:
            with open(file_path, 'rb') as f:
                self.target_file = f.read()
            logger.info(f" Arquivo carregado: {file_path.name} ({len(self.target_file)} bytes)")
        except Exception as e:
            logger.error(f" Erro ao carregar arquivo: {e}")
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
        
        return True
    
    def search_csv_for_text(self, search_text: str, case_sensitive: bool = False) -> List[Dict]:
        """Busca o texto no CSV de traduções."""
        
        if self.csv_data is None:
            return []
        
        results = []
        flags = 0 if case_sensitive else re.IGNORECASE
        
        try:
            # Busca no texto original
            for idx, row in self.csv_data.iterrows():
                original_text = str(row.get('texto', ''))
                translated_text = str(row.get('texto_traduzido', ''))
                offset = str(row.get('offset', ''))
                
                # Busca no texto original
                if re.search(re.escape(search_text), original_text, flags):
                    results.append({
                        'source': 'csv_original',
                        'offset': offset,
                        'text': original_text,
                        'translated': translated_text,
                        'encoding': str(row.get('encoding', 'N/A')),
                        'size': str(row.get('tamanho_bytes', row.get('size', 'N/A')))
                    })
                
                # Busca no texto traduzido
                elif re.search(re.escape(search_text), translated_text, flags):
                    results.append({
                        'source': 'csv_translated',
                        'offset': offset,
                        'text': translated_text,
                        'original': original_text,
                        'encoding': str(row.get('encoding', 'N/A')),
                        'size': str(row.get('tamanho_bytes', row.get('size', 'N/A')))
                    })
        
        except Exception as e:
            logger.warning(f"Erro ao buscar no CSV: {e}")
        
        return results
    
    def encode_text_for_search(self, text: str) -> Dict[str, bytes]:
        """Codifica o texto de busca em diferentes encodings."""
        
        encoded_variants = {}
        
        for encoding in self.encodings:
            try:
                encoded = text.encode(encoding)
                encoded_variants[encoding] = encoded
            except UnicodeEncodeError as e:
                if self.verbose:
                    logger.warning(f"Não foi possível codificar em {encoding}: {e}")
        
        return encoded_variants
    
    def search_binary_data(self, search_text: str, case_sensitive: bool = False, 
                          search_type: str = 'exact', max_results: int = 100) -> List[Dict]:
        """Busca o texto nos dados binários do arquivo."""
        
        if self.target_file is None:
            return []
        
        results = []
        
        # Se for busca hexadecimal
        if search_text.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in search_text.replace(' ', '')):
            return self._search_hex_pattern(search_text, max_results)
        
        # Busca por texto
        encoded_variants = self.encode_text_for_search(search_text)
        
        for encoding, encoded_text in encoded_variants.items():
            try:
                if search_type == 'exact':
                    # Busca exata
                    if not case_sensitive and encoding in ['ascii', 'latin-1']:
                        # Para ASCII/Latin-1, podemos fazer busca case-insensitive
                        lower_encoded = search_text.lower().encode(encoding)
                        upper_encoded = search_text.upper().encode(encoding)
                        
                        # Busca ambas as variações
                        for variant, variant_name in [(lower_encoded, 'lower'), (upper_encoded, 'upper')]:
                            positions = self._find_all_positions(self.target_file, variant)
                            for pos in positions:
                                if len(results) >= max_results:
                                    break
                                results.append({
                                    'offset': pos,
                                    'hex_offset': f"0x{pos:x}",
                                    'encoding': encoding,
                                    'search_variant': variant_name,
                                    'found_bytes': variant,
                                    'context_start': max(0, pos - 50),
                                    'context_end': min(len(self.target_file), pos + len(variant) + 50)
                                })
                    else:
                        # Busca case-sensitive ou encodings que não suportam case-insensitive simples
                        positions = self._find_all_positions(self.target_file, encoded_text)
                        for pos in positions:
                            if len(results) >= max_results:
                                break
                            results.append({
                                'offset': pos,
                                'hex_offset': f"0x{pos:x}",
                                'encoding': encoding,
                                'search_variant': 'exact',
                                'found_bytes': encoded_text,
                                'context_start': max(0, pos - 50),
                                'context_end': min(len(self.target_file), pos + len(encoded_text) + 50)
                            })
                
                elif search_type == 'partial':
                    # Busca parcial (cada palavra separadamente)
                    words = search_text.split()
                    for word in words:
                        word_encoded = word.encode(encoding)
                        positions = self._find_all_positions(self.target_file, word_encoded)
                        for pos in positions:
                            if len(results) >= max_results:
                                break
                            results.append({
                                'offset': pos,
                                'hex_offset': f"0x{pos:x}",
                                'encoding': encoding,
                                'search_variant': f'partial_word_{word}',
                                'found_bytes': word_encoded,
                                'context_start': max(0, pos - 50),
                                'context_end': min(len(self.target_file), pos + len(word_encoded) + 50)
                            })
                
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Erro na busca com encoding {encoding}: {e}")
        
        # Remove duplicatas (mesmo offset)
        unique_results = []
        seen_offsets = set()
        
        for result in sorted(results, key=lambda x: x['offset']):
            if result['offset'] not in seen_offsets:
                unique_results.append(result)
                seen_offsets.add(result['offset'])
        
        return unique_results
    
    def _search_hex_pattern(self, hex_pattern: str, max_results: int = 100) -> List[Dict]:
        """Busca por padrão hexadecimal."""
        
        # Limpa e normaliza o padrão hex
        clean_hex = hex_pattern.replace('0x', '').replace(' ', '').replace('\\x', '')
        
        try:
            # Converte para bytes
            pattern_bytes = bytes.fromhex(clean_hex)
        except ValueError as e:
            logger.error(f"Padrão hexadecimal inválido: {hex_pattern} - {e}")
            return []
        
        results = []
        positions = self._find_all_positions(self.target_file, pattern_bytes)
        
        for pos in positions[:max_results]:
            results.append({
                'offset': pos,
                'hex_offset': f"0x{pos:x}",
                'encoding': 'hex_pattern',
                'search_variant': 'hex',
                'found_bytes': pattern_bytes,
                'context_start': max(0, pos - 50),
                'context_end': min(len(self.target_file), pos + len(pattern_bytes) + 50)
            })
        
        return results
    
    def _find_all_positions(self, data: bytes, pattern: bytes) -> List[int]:
        """Encontra todas as posições onde o padrão ocorre nos dados."""
        
        positions = []
        start = 0
        
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        return positions
    
    def get_context_data(self, offset: int, context_size: int = 100) -> Dict:
        """Obtém dados de contexto ao redor do offset."""
        
        if self.target_file is None or offset >= len(self.target_file):
            return {}
        
        start = max(0, offset - context_size)
        end = min(len(self.target_file), offset + context_size)
        
        context_data = self.target_file[start:end]
        
        # Tenta decodificar o contexto
        decoded_context = {}
        for encoding in self.encodings:
            try:
                decoded = context_data.decode(encoding, errors='ignore')
                # Limpa caracteres de controle
                clean_decoded = ''.join(
                    c if ord(c) >= 32 or c in ['\n', '\t'] 
                    else f'\\x{ord(c):02x}' 
                    for c in decoded
                )
                decoded_context[encoding] = clean_decoded
            except:
                decoded_context[encoding] = "ERRO"
        
        return {
            'raw_data': context_data,
            'decoded': decoded_context,
            'start_offset': start,
            'end_offset': end,
            'target_position': offset - start
        }
    
    def search_text(self, search_text: str, case_sensitive: bool = False,
                   search_type: str = 'exact', max_results: int = 100,
                   context_size: int = 100, search_csv: bool = True) -> Dict:
        """Busca principal por texto."""
        
        logger.info(f"\n{'='*60}")
        logger.info(f" BUSCANDO TEXTO: '{search_text}'")
        logger.info(f"{'='*60}")
        logger.info(f" Configurações:")
        logger.info(f"   Case sensitive: {case_sensitive}")
        logger.info(f"   Tipo de busca: {search_type}")
        logger.info(f"   Max resultados: {max_results}")
        logger.info(f"   Tamanho contexto: {context_size}")
        logger.info(f"   Buscar no CSV: {search_csv}")
        
        results = {
            'search_text': search_text,
            'csv_results': [],
            'binary_results': [],
            'summary': {}
        }
        
        # Busca no CSV se solicitado
        if search_csv:
            logger.info(f"\n Buscando no CSV...")
            csv_results = self.search_csv_for_text(search_text, case_sensitive)
            results['csv_results'] = csv_results
            
            if csv_results:
                logger.info(f" Encontrado {len(csv_results)} resultado(s) no CSV:")
                for i, result in enumerate(csv_results):
                    logger.info(f"   [{i+1}] Offset: {result['offset']} ({result['source']})")
                    logger.info(f"       Texto: '{result['text'][:60]}{'...' if len(result['text']) > 60 else ''}'")
            else:
                logger.info(f" Nenhum resultado encontrado no CSV.")
        
        # Busca nos dados binários
        logger.info(f"\n Buscando nos dados binários...")
        binary_results = self.search_binary_data(search_text, case_sensitive, search_type, max_results)
        results['binary_results'] = binary_results
        
        if binary_results:
            logger.info(f" Encontrado {len(binary_results)} resultado(s) nos dados binários:")
            
            for i, result in enumerate(binary_results):
                logger.info(f"\n   RESULTADO [{i+1}]:")
                logger.info(f"     Offset: {result['hex_offset']} ({result['offset']})")
                logger.info(f"     Encoding: {result['encoding']}")
                logger.info(f"     Variante: {result['search_variant']}")
                logger.info(f"     Bytes encontrados: {result['found_bytes'].hex()}")
                
                # Adiciona contexto
                context = self.get_context_data(result['offset'], context_size)
                if context:
                    result['context'] = context
                    
                    logger.info(f"     Contexto (offset {context['start_offset']}-{context['end_offset']}):")
                    
                    # Mostra contexto hex
                    hex_context = context['raw_data']
                    for j in range(0, min(len(hex_context), 64), 16):
                        chunk = hex_context[j:j+16]
                        addr = context['start_offset'] + j
                        hex_part = ' '.join(f'{b:02x}' for b in chunk)
                        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                        
                        marker = " <-- TARGET" if context['start_offset'] + j <= result['offset'] < context['start_offset'] + j + 16 else ""
                        logger.info(f"       {addr:08x}: {hex_part:<48} |{ascii_part}|{marker}")
                    
                    # Mostra contexto decodificado
                    for encoding, decoded in context['decoded'].items():
                        if decoded and not decoded.startswith('ERRO') and len(decoded.strip()) > 0:
                            logger.info(f"     Contexto {encoding}: '{decoded[:100]}{'...' if len(decoded) > 100 else ''}'")
                            break
        else:
            logger.info(f" Nenhum resultado encontrado nos dados binários.")
        
        # Resumo
        results['summary'] = {
            'csv_matches': len(results['csv_results']),
            'binary_matches': len(results['binary_results']),
            'total_matches': len(results['csv_results']) + len(results['binary_results'])
        }
        
        logger.info(f"\n RESUMO DA BUSCA:")
        logger.info(f"   Resultados no CSV: {results['summary']['csv_matches']}")
        logger.info(f"   Resultados nos dados binários: {results['summary']['binary_matches']}")
        logger.info(f"   Total de resultados: {results['summary']['total_matches']}")
        
        return results
    
    def export_results_to_csv(self, results: Dict, output_path: Path):
        """Exporta os resultados para um arquivo CSV."""
        
        try:
            export_data = []
            
            # Adiciona resultados do CSV
            for result in results['csv_results']:
                export_data.append({
                    'source': result['source'],
                    'offset': result['offset'],
                    'hex_offset': result['offset'],  # Será convertido se necessário
                    'encoding': result.get('encoding', 'N/A'),
                    'text': result['text'],
                    'search_variant': 'csv_match',
                    'context': f"Original: {result.get('original', result.get('translated', 'N/A'))}"
                })
            
            # Adiciona resultados binários
            for result in results['binary_results']:
                context_text = ""
                if 'context' in result and result['context']['decoded']:
                    for encoding, decoded in result['context']['decoded'].items():
                        if decoded and not decoded.startswith('ERRO'):
                            context_text = decoded[:200]
                            break
                
                export_data.append({
                    'source': 'binary_search',
                    'offset': result['offset'],
                    'hex_offset': result['hex_offset'],
                    'encoding': result['encoding'],
                    'text': result['found_bytes'].hex(),
                    'search_variant': result['search_variant'],
                    'context': context_text
                })
            
            # Cria DataFrame e salva
            df = pd.DataFrame(export_data)
            df.to_csv(output_path, index=False, encoding='utf-8', sep='\t')
            
            logger.info(f"Resultados exportados para: {output_path}")
            
        except Exception as e:
            logger.error(f"Erro ao exportar resultados: {e}")


def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Text to Offset Finder - Busca offsets por texto",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --vox --text "Continue"               # Busca 'Continue' no VOX.DAT do CD1
  %(prog)s --demo --text "Snake" --case-sensitive # Busca case-sensitive no DEMO.DAT
  %(prog)s --cd CD2 --radio --text "Metal Gear"  # Busca no RADIO.DAT do CD2
  %(prog)s --list                                # Lista arquivos disponíveis
  %(prog)s --brf --text "0x00ff4d65"            # Busca padrão hexadecimal
  %(prog)s --stage --text "Solid" --export results.csv # Exporta resultados
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
            help=f"Busca em {file_descriptions[file_key]}"
        )
    
    # Argumentos para compatibilidade com versão anterior
    compat_group = parser.add_argument_group('Compatibilidade (argumentos antigos)')
    compat_group.add_argument(
        "--file", 
        type=Path,
        help="Caminho específico do arquivo (compatibilidade)"
    )
    compat_group.add_argument(
        "--csv", 
        type=Path,
        help="Caminho específico do CSV (compatibilidade)"
    )
    
    # Configurações de busca
    search_group = parser.add_argument_group('Configurações de busca')
    search_group.add_argument(
        "--text", 
        help="Texto para buscar"
    )
    search_group.add_argument(
        "--case-sensitive", 
        action="store_true",
        help="Busca case-sensitive"
    )
    search_group.add_argument(
        "--type", 
        choices=['exact', 'partial'], 
        default='exact',
        help="Tipo de busca (exact/partial)"
    )
    search_group.add_argument(
        "--max-results", 
        type=int, 
        default=100,
        help="Máximo de resultados (default: 100)"
    )
    search_group.add_argument(
        "--context-size", 
        type=int, 
        default=100,
        help="Tamanho do contexto (default: 100)"
    )
    search_group.add_argument(
        "--no-csv", 
        action="store_true",
        help="Não buscar no CSV"
    )
    
    # Outras opções
    other_group = parser.add_argument_group('Outras opções')
    other_group.add_argument(
        "--export", 
        type=Path,
        help="Exportar resultados para CSV"
    )
    other_group.add_argument(
        "--verbose", "-v", 
        action="store_true",
        default=True,
        help="Saída detalhada (padrão: habilitado)"
    )
    
    return parser


def main():
    """Função principal do finder."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Resolver arquivos
    file_resolver = FileResolver(args.cd)
    
    # Lista arquivos e sai se solicitado
    if args.list:
        print(f"\n Arquivos disponíveis em {args.cd}:")
        print("-" * 70)
        available = file_resolver.list_available_files()
        if available:
            for line in available:
                print(f"  {line}")
        else:
            print(f"   Diretório {args.cd} não encontrado")
        print(f"\nUso: {parser.prog} --cd {args.cd} --<arquivo> --text 'texto'")
        print(f"Exemplo: {parser.prog} --cd {args.cd} --vox --text 'Continue'")
        return
    
    # Valida se --text foi fornecido (obrigatório exceto para --list)
    if not args.text:
        logger.error("Argumento --text é obrigatório")
        parser.print_help()
        return
    
    # Determina arquivo e CSV para busca
    target_file = None
    target_csv = None
    
    if args.file:
        # Compatibilidade: usa arquivo especificado
        target_file = args.file
        target_csv = args.csv
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
            logger.info(f"Use --list para ver arquivos disponíveis ou especifique um arquivo com --vox, --radio, etc.")
            return
        elif len(selected_files) > 1:
            logger.error(f"Múltiplos arquivos selecionados: {', '.join(selected_files)}")
            logger.info("Selecione apenas um arquivo por vez para busca")
            return
        
        # Resolve arquivo selecionado
        file_key = selected_files[0]
        target_file = file_resolver.get_file_path(file_key)
        target_csv = file_resolver.get_csv_path(file_key) if not args.no_csv else None
        
        if not target_file:
            logger.error(f"Arquivo não encontrado: {file_key} ({args.cd})")
            return
        
        logger.info(f" Arquivo selecionado: {file_key} -> {target_file.name}")
        if target_csv:
            logger.info(f" CSV encontrado: {target_csv.name}")
        else:
            logger.info(f" CSV não encontrado para {file_key}")
    
    # Valida arquivo
    if not target_file or not target_file.exists():
        logger.error(f"Arquivo não encontrado: {target_file}")
        return
    
    # Cria e executa o finder
    finder = TextOffsetFinder(verbose=getattr(args, 'verbose', True))
    
    if not finder.load_file(target_file, target_csv):
        logger.error("Falha ao carregar arquivo!")
        return
    
    # Executa busca
    results = finder.search_text(
        search_text=args.text,
        case_sensitive=args.case_sensitive,
        search_type=args.type,
        max_results=args.max_results,
        context_size=args.context_size,
        search_csv=not args.no_csv
    )
    
    # Exporta se solicitado
    if args.export:
        finder.export_results_to_csv(results, args.export)
    
    logger.info(f"\n BUSCA CONCLUÍDA!")
    
    # Mostra offsets encontrados para uso com o offset_analyzer
    if results['binary_results']:
        offsets = [result['hex_offset'] for result in results['binary_results']]
        logger.info(f"\n Para analisar com offset_analyzer.py:")
        logger.info(f"python tools/offset_analyzer.py --offsets {' '.join(offsets)}")


if __name__ == "__main__":
    
    main()

    """
    Exemplos de uso:
    
    # Busca texto no VOX.DAT do CD1
    python tools/text_finder.py --vox --text "Continue"
    
    # Busca case-sensitive no DEMO.DAT
    python tools/text_finder.py --demo --text "Metal Gear" --case-sensitive
    
    # Busca no RADIO.DAT do CD2 (quando disponível)
    python tools/text_finder.py --cd CD2 --radio --text "Snake"
    
    # Busca parcial (palavras separadas)
    python tools/text_finder.py --stage --text "Solid Snake" --type partial
    
    # Busca padrão hexadecimal
    python tools/text_finder.py --brf --text "0x00ff4d65"
    
    # Lista arquivos disponíveis
    python tools/text_finder.py --list
    
    # Exporta resultados
    python tools/text_finder.py --face --text "Continue" --export results.csv
    
    # Busca apenas nos dados binários (ignora CSV)
    python tools/text_finder.py --vox --text "Solid" --no-csv
    
    # Compatibilidade com versão anterior
    python tools/text_finder.py --file caminho/arquivo.dat --text "texto"
    """
    