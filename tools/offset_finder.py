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

# Adiciona o diretório raiz ao sys.path
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

logger = setup_logger()

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
            logger.info(f" Arquivo carregado: {len(self.target_file)} bytes")
        except Exception as e:
            logger.error(f" Erro ao carregar arquivo: {e}")
            return False
        
        # Carrega CSV se fornecido
        if csv_path and csv_path.exists():
            try:
                self.csv_data = pd.read_csv(csv_path, delimiter="\t")
                logger.info(f" CSV carregado: {len(self.csv_data)} entradas")
            except Exception as e:
                logger.warning(f" Erro ao carregar CSV: {e}")
        
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
                        'size': str(row.get('size', 'N/A'))
                    })
                
                # Busca no texto traduzido
                elif re.search(re.escape(search_text), translated_text, flags):
                    results.append({
                        'source': 'csv_translated',
                        'offset': offset,
                        'text': translated_text,
                        'original': original_text,
                        'encoding': str(row.get('encoding', 'N/A')),
                        'size': str(row.get('size', 'N/A'))
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


def main():
    """Função principal do finder."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Text to Offset Finder - Busca offsets por texto")
    parser.add_argument("--file", type=Path, 
                       default=BASE_DIR / "assets" / "fontes" / "CD1" / "DEMO.DAT",
                       help="Arquivo para busca")
    parser.add_argument("--csv", type=Path,
                       default=BASE_DIR / "translated" / "strings_DEMO_traduzido.csv",
                       help="Arquivo CSV com traduções")
    parser.add_argument("--text", required=True,
                       help="Texto para buscar")
    parser.add_argument("--case-sensitive", action="store_true",
                       help="Busca case-sensitive")
    parser.add_argument("--type", choices=['exact', 'partial'], default='exact',
                       help="Tipo de busca (exact/partial)")
    parser.add_argument("--max-results", type=int, default=100,
                       help="Máximo de resultados (default: 100)")
    parser.add_argument("--context-size", type=int, default=100,
                       help="Tamanho do contexto (default: 100)")
    parser.add_argument("--no-csv", action="store_true",
                       help="Não buscar no CSV")
    parser.add_argument("--export", type=Path,
                       help="Exportar resultados para CSV")
    
    args = parser.parse_args()
    
    # Valida arquivo
    if not args.file.exists():
        logger.error(f"Arquivo não encontrado: {args.file}")
        sys.exit(1)
    
    # Cria e executa o finder
    finder = TextOffsetFinder()
    
    if not finder.load_file(args.file, args.csv if not args.no_csv else None):
        logger.error("Falha ao carregar arquivo!")
        sys.exit(1)
    
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
    """
    Exemplos de uso:
    
    # Busca texto exato
    python tools/text_finder.py --text "Don't move!!!"
    
    # Busca case-sensitive
    python tools/text_finder.py --text "Is this the first time you ever|pointed a gun at a person?" --case-sensitive
    
    # Busca parcial (palavras separadas)
    python tools/text_finder.py --text "Metal Gear" --type partial
    
    # Busca padrão hexadecimal
    python tools/text_finder.py --text "0x00ff4d65"
    
    # Exporta resultados
    python tools/text_finder.py --text "Continue" --export results.csv
    
    # Busca apenas nos dados binários (ignora CSV)
    python tools/text_finder.py --text "Solid" --no-csv
    """
    
    main()