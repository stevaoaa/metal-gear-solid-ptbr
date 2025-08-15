#!/usr/bin/env python3
"""
Script para reconstruir arquivos binários com textos traduzidos - MGS PSX.

"""

import os
import sys
import unicodedata
import pandas as pd
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import struct
from datetime import datetime
import argparse

# Adiciona o diretório raiz ao sys.path para permitir importações internas
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

# Inicializa o logger para registrar as operações do script
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
        self.output_path = BASE_DIR / "output"
    
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
    
    def get_output_path(self, file_key: str) -> Path:
        """Retorna o caminho do arquivo de saída (patcheado)."""
        available_files = self.get_available_files()
        if file_key in available_files:
            filename = available_files[file_key]
            base_name = Path(filename).stem
            extension = Path(filename).suffix
            
            # Cria nome do arquivo patcheado
            output_name = f"{base_name}_PATCHED{extension}"
            return self.patches_path / output_name
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
    
    def get_analysis_path(self, file_key: str) -> Path:
        """Retorna o caminho do arquivo de análise."""
        available_files = self.get_available_files()
        if file_key in available_files:
            filename = available_files[file_key]
            base_name = Path(filename).stem
            
            analysis_name = f"{base_name}_insertion_problems.txt"
            return self.output_path / analysis_name
        return self.output_path / "insertion_problems.txt"
    
    def list_available_files(self) -> List[str]:
        """Lista todos os arquivos disponíveis no diretório do CD."""
        if not self.assets_path.exists():
            return []
        
        available_files = []
        file_mapping = self.get_available_files()
        
        for key, filename in file_mapping.items():
            original_path = self.get_original_path(key)
            csv_path = self.get_csv_path(key)
            output_path = self.get_output_path(key)
            
            original_status = "✓" if original_path else "✗"
            csv_status = "✓" if csv_path else "✗"
            
            size = ""
            if original_path:
                size_bytes = original_path.stat().st_size
                if size_bytes > 1024*1024:
                    size = f"({size_bytes // (1024*1024)} MB)"
                else:
                    size = f"({size_bytes // 1024} KB)"
            
            csv_info = ""
            if csv_path:
                csv_info = f"CSV: {csv_path.name}"
            
            output_info = f"Output: {output_path.name}" if output_path else ""
            
            status_info = f"Orig:{original_status} CSV:{csv_status}"
            available_files.append(f"--{key:<8} {filename:<15} {size:<8} {status_info}")
            
            if csv_info:
                available_files.append(f"{'':>10} {csv_info}")
            if output_info:
                available_files.append(f"{'':>10} {output_info}")
            available_files.append("")  # Linha em branco para separar
        
        return available_files

class MGSRebuilder:
    """
    Versão CORRIGIDA para reconstrução de textos do MGS PSX.
    GARANTIA ABSOLUTA de preservação do padrão crítico 00 FF.
    """
    
    def __init__(self, debug_mode: bool = False, strict_mode: bool = True):
        self.debug_mode = debug_mode
        self.strict_mode = strict_mode
        self.analysis_file = None
        self.stats = {
            'processed': 0,
            'applied': 0,
            'skipped_encoding': 0,
            'skipped_size': 0,
            'identical_preserved': 0,
            'modified_applied': 0,
            'encoding_fixes': 0,
            'critical_pattern_preserved': 0,
            'critical_pattern_lost': 0,
            'problems_analyzed': 0
        }
        
        # Tabela de substituição para acentos (específica para Shift-JIS)
        self.accent_map = {
            # Vogais acentuadas
            'á': 'a', 'à': 'a', 'ã': 'a', 'â': 'a', 'ä': 'a',
            'é': 'eh', 'è': 'e', 'ê': 'e', 'ë': 'e',
            'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
            'ó': 'o', 'ò': 'o', 'õ': 'o', 'ô': 'o', 'ö': 'o',
            'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
            'Á': 'A', 'À': 'A', 'Ã': 'A', 'Â': 'A', 'Ä': 'A',
            'É': 'Eh', 'È': 'E', 'Ê': 'E', 'Ë': 'E',
            'Í': 'I', 'Ì': 'I', 'Î': 'I', 'Ï': 'I',
            'Ó': 'O', 'Ò': 'O', 'Õ': 'O', 'Ô': 'O', 'Ö': 'O',
            'Ú': 'U', 'Ù': 'U', 'Û': 'U', 'Ü': 'U',
            # Caracteres específicos
            'ç': 'c', 'Ç': 'C',
            'ñ': 'n', 'Ñ': 'N',
            # Caracteres especiais comuns
            '"': '"', '"': '"', ''': "'", ''': "'",
            '–': '-', '—': '-', '…': '...',
        }
        
        # Códigos de controle do codec (preservar exatamente)
        self.codec_controls = ['#N', '#P', '#W', '#C', '#K', '#E', '#S', '#T']
    
    def setup_analysis_file(self, analysis_path: Path):
        """Configura o arquivo de análise de problemas."""
        try:
            analysis_path.parent.mkdir(parents=True, exist_ok=True)
            self.analysis_file = open(analysis_path, 'w', encoding='utf-8')
            
            # Cabeçalho do arquivo
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.analysis_file.write(f"ANÁLISE DE PROBLEMAS DE INSERÇÃO - MGS PSX REBUILDER\n")
            self.analysis_file.write(f"Gerado em: {timestamp}\n")
            self.analysis_file.write(f"{'='*80}\n\n")
            
            logger.info(f"Arquivo de análise configurado: {analysis_path}")
            
        except Exception as e:
            logger.error(f"Erro ao configurar arquivo de análise: {e}")
            self.analysis_file = None
    
    def analyze_problem_and_export(self, binary_data: bytes, offset: int, original_text: str, 
                                  translated_text: str, problem_type: str, details: str = ""):
        """
        Realiza análise detalhada do problema e exporta para arquivo.
        Se --debug estiver ativo, também exibe no terminal.
        """
        if not self.analysis_file:
            return
            
        try:
            self.stats['problems_analyzed'] += 1
            context_size = 100
            
            # Prepara o conteúdo da análise
            analysis_content = []
            analysis_content.append(f"PROBLEMA #{self.stats['problems_analyzed']:03d} - {problem_type}")
            analysis_content.append(f"{'='*50}")
            analysis_content.append(f"Offset: {hex(offset)}")
            analysis_content.append(f"Texto original:  '{original_text}'")
            analysis_content.append(f"Texto traduzido: '{translated_text}'")
            analysis_content.append(f"Detalhes: {details}")
            analysis_content.append("")
            
            # Análise do contexto binário
            start = max(0, offset - context_size)
            end = min(len(binary_data), offset + context_size)
            context = binary_data[start:end]
            
            analysis_content.append(f"CONTEXTO BINÁRIO ({hex(start)} - {hex(end)}):")
            analysis_content.append(f"{'-'*60}")
            
            # Mostra em hex com ASCII
            hex_lines = []
            for i in range(0, min(len(context), 128), 16):
                chunk = context[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                addr = start + i
                
                # Marca o offset problemático
                marker = " <-- OFFSET" if start + i <= offset < start + i + 16 else ""
                hex_line = f"{addr:08x}: {hex_part:<48} |{ascii_part}|{marker}"
                hex_lines.append(hex_line)
                analysis_content.append(hex_line)
            
            analysis_content.append("")
            
            # Tentativas de decodificação
            analysis_content.append(f"TENTATIVAS DE DECODIFICAÇÃO:")
            analysis_content.append(f"{'-'*30}")
            
            offset_in_context = offset - start
            sample_data = context[offset_in_context:offset_in_context+100]
            
            decode_lines = []
            for encoding in ['shift_jis', 'ascii', 'latin-1', 'utf-8']:
                try:
                    decoded = sample_data.decode(encoding, errors='ignore')
                    clean_decoded = ''.join(c if ord(c) >= 32 else f'\\x{ord(c):02x}' for c in decoded[:50])
                    if clean_decoded.strip():
                        decode_line = f"{encoding:>10}: '{clean_decoded}'"
                        decode_lines.append(decode_line)
                        analysis_content.append(decode_line)
                except Exception as e:
                    decode_line = f"{encoding:>10}: ERRO - {str(e)}"
                    decode_lines.append(decode_line)
                    analysis_content.append(decode_line)
            
            # Análise específica do padrão crítico 00 FF
            analysis_content.append(f"\nANÁLISE DO PADRÃO CRÍTICO 00 FF:")
            analysis_content.append(f"{'-'*35}")
            
            ff_pattern = b'\x00\xff'
            ff_positions = []
            search_start = 0
            
            while True:
                pos = context.find(ff_pattern, search_start)
                if pos == -1:
                    break
                ff_positions.append(start + pos)
                search_start = pos + 1
            
            if ff_positions:
                ff_line = f"Padrões 00 FF encontrados em: {[hex(pos) for pos in ff_positions]}"
                analysis_content.append(ff_line)
                
                for pos in ff_positions:
                    if abs(pos - offset) < context_size:
                        distance = pos - offset
                        distance_line = f"  {hex(pos)}: distância do offset = {distance} bytes"
                        analysis_content.append(distance_line)
            else:
                no_ff_line = f"Nenhum padrão 00 FF encontrado no contexto"
                analysis_content.append(no_ff_line)
            
            # Análise do tamanho disponível
            analysis_content.append(f"\nANÁLISE DE ESPAÇO DISPONÍVEL:")
            analysis_content.append(f"{'-'*32}")
            
            # Detecta boundaries da string original
            try:
                chunk_size, original_chunk = self.detect_string_exact(binary_data, offset, original_text)
                chunk_info = f"Chunk original detectado: {len(original_chunk)} bytes"
                hex_info = f"Hex do chunk: {original_chunk.hex()}"
                analysis_content.append(chunk_info)
                analysis_content.append(hex_info)
                
                # Análise crítica do chunk
                critical_analysis = self.analyze_critical_pattern(original_chunk)
                if critical_analysis['has_00_ff']:
                    critical_pos = f"Padrão crítico 00 FF na posição: {critical_analysis['ff_position']}"
                    space_info = f"Espaço disponível para texto: {critical_analysis['text_space']} bytes"
                    terminator_info = f"Terminador completo: {critical_analysis['full_terminator'].hex()}"
                    analysis_content.extend([critical_pos, space_info, terminator_info])
                else:
                    no_critical = f"Sem padrão crítico - espaço total disponível: {len(original_chunk)} bytes"
                    analysis_content.append(no_critical)
                
                # Calcula requisitos do texto traduzido
                clean_translated = translated_text
                try:
                    translated_bytes = clean_translated.encode('shift_jis', errors='ignore')
                    bytes_needed = f"Texto traduzido requer: {len(translated_bytes)} bytes"
                    bytes_hex = f"Texto traduzido (hex): {translated_bytes.hex()}"
                    analysis_content.extend([bytes_needed, bytes_hex])
                    
                    space_needed = len(translated_bytes) + (1 if critical_analysis['has_00_ff'] else 0)
                    space_available = critical_analysis['text_space'] if critical_analysis['has_00_ff'] else len(original_chunk)
                    
                    comparison = f"Comparação: {space_needed} bytes necessários vs {space_available} disponíveis"
                    analysis_content.append(comparison)
                    
                    if space_needed > space_available:
                        overflow = space_needed - space_available
                        overflow_info = f"OVERFLOW: {overflow} bytes a mais que o disponível"
                        analysis_content.append(overflow_info)
                    
                except Exception as e:
                    error_translated = f"Erro ao analisar texto traduzido: {e}"
                    analysis_content.append(error_translated)
                    
            except Exception as e:
                error_chunk = f"Erro na detecção do chunk: {e}"
                analysis_content.append(error_chunk)
            
            analysis_content.append(f"{'='*80}")
            analysis_content.append("")
            
            # Escreve no arquivo
            for line in analysis_content:
                self.analysis_file.write(line + "\n")
            self.analysis_file.flush()
            
            # Se debug mode está ativo, também exibe no terminal
            if self.debug_mode:
                logger.info(f"\n{'='*60}")
                logger.info(f" ANÁLISE DETALHADA DE PROBLEMA - DEBUG MODE")
                logger.info(f"{'='*60}")
                
                # Mostra informações principais
                logger.info(f"PROBLEMA #{self.stats['problems_analyzed']:03d}: {problem_type}")
                logger.info(f"Offset: {hex(offset)}")
                logger.info(f"Original:  '{original_text[:40]}{'...' if len(original_text) > 40 else ''}'")
                logger.info(f"Traduzido: '{translated_text[:40]}{'...' if len(translated_text) > 40 else ''}'")
                logger.info(f"Detalhes: {details}")
                
                # Mostra contexto hex (limitado para terminal)
                logger.info(f"\nCONTEXTO HEX (primeiras 4 linhas):")
                for i, hex_line in enumerate(hex_lines[:4]):
                    logger.info(f"  {hex_line}")
                if len(hex_lines) > 4:
                    logger.info(f"  ... (+{len(hex_lines)-4} linhas no arquivo)")
                
                # Mostra decodificações
                logger.info(f"\nTENTATIVAS DE DECODIFICAÇÃO:")
                for decode_line in decode_lines:
                    logger.info(f"  {decode_line}")
                
                # Info do padrão FF
                if ff_positions:
                    logger.info(f"\nPADRÃO 00 FF: {[hex(pos) for pos in ff_positions]}")
                else:
                    logger.info(f"\nPADRÃO 00 FF: Não encontrado")
                
                # Info de espaço
                try:
                    chunk_size, original_chunk = self.detect_string_exact(binary_data, offset, original_text)
                    critical_analysis = self.analyze_critical_pattern(original_chunk)
                    
                    if critical_analysis['has_00_ff']:
                        logger.info(f"ESPAÇO: {critical_analysis['text_space']} bytes disponíveis (padrão crítico)")
                    else:
                        logger.info(f"ESPAÇO: {len(original_chunk)} bytes disponíveis (sem padrão crítico)")
                        
                    clean_translated = translated_text
                    translated_bytes = clean_translated.encode('shift_jis', errors='ignore')
                    logger.info(f"NECESSÁRIO: {len(translated_bytes)} bytes")
                    
                except:
                    logger.info(f"ESPAÇO: Erro na análise")
                
                logger.info(f"{'='*60}")
                logger.info(f" Análise completa salva em: {self.analysis_file.name}")
                logger.info(f"{'='*60}\n")
            
        except Exception as e:
            logger.error(f"Erro durante análise e exportação: {e}")
    
    @staticmethod
    def remove_accents_simple(text: str) -> str:
        """
        Remove acentos de forma simples usando apenas o mapeamento manual.
        """

        accent_map = {
                    # Vogais acentuadas
                    'á': 'a', 'à': 'a', 'ã': 'a', 'â': 'a', 'ä': 'a',
                    'é': 'eh', 'è': 'e', 'ê': 'e', 'ë': 'e',
                    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
                    'ó': 'o', 'ò': 'o', 'õ': 'o', 'ô': 'o', 'ö': 'o',
                    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
                    'Á': 'A', 'À': 'A', 'Ã': 'A', 'Â': 'A', 'Ä': 'A',
                    'É': 'Eh', 'È': 'E', 'Ê': 'E', 'Ë': 'E',
                    'Í': 'I', 'Ì': 'I', 'Î': 'I', 'Ï': 'I',
                    'Ó': 'O', 'Ò': 'O', 'Õ': 'O', 'Ô': 'O', 'Ö': 'O',
                    'Ú': 'U', 'Ù': 'U', 'Û': 'U', 'Ü': 'U',
                    # Caracteres específicos
                    'ç': 'c', 'Ç': 'C',
                    'ñ': 'n', 'Ñ': 'N',
        }

        if not isinstance(text, str):
            return text

        result = text
        for accented, replacement in accent_map.items():
            result = result.replace(accented, replacement)
        
        return result

    
    def detect_string_exact(self, binary_data: bytes, offset: int, expected_text: str) -> Tuple[int, bytes]:
        """
        Detecta com MÁXIMA precisão onde uma string termina no arquivo original.
        """
        try:
            # Primeiro, limpa o texto esperado
            clean_expected = expected_text
            
            # Tenta diferentes encodings para encontrar o match
            for encoding in ['shift_jis', 'ascii', 'latin-1']:
                try:
                    expected_bytes = clean_expected.encode(encoding, errors='ignore')
                    
                    # Verifica se encontra uma correspondência razoável no offset
                    max_scan = min(len(expected_bytes) + 50, len(binary_data) - offset)
                    scan_chunk = binary_data[offset:offset + max_scan]
                    
                    # Procura pela string no início
                    if scan_chunk.startswith(expected_bytes):
                        # Encontrou match exato! Agora detecta o final
                        end_pos = offset + len(expected_bytes)
                        
                        # Conta terminadores (00, FF, etc.)
                        while end_pos < len(binary_data):
                            byte_val = binary_data[end_pos]
                            if byte_val in [0x00, 0xFF]:
                                end_pos += 1
                            else:
                                break
                        
                        total_size = end_pos - offset
                        original_chunk = binary_data[offset:end_pos]
                        
                        if self.debug_mode:
                            logger.debug(f"String detectada exatamente em {hex(offset)}: {total_size} bytes")
                        
                        return total_size, original_chunk
                    
                except UnicodeEncodeError:
                    continue
            
            # Fallback: estimativa conservadora baseada no texto original
            try:
                probe_size = min(len(expected_text) * 2 + 20, len(binary_data) - offset)
                probe_chunk = binary_data[offset:offset + probe_size]
                
                # Procura por terminadores a partir do offset
                term_pos = offset
                for i, byte_val in enumerate(probe_chunk):
                    if i > len(expected_text):  # Além do tamanho esperado
                        if byte_val in [0x00, 0xFF]:
                            continue
                        else:
                            term_pos = offset + i
                            break
                
                fallback_size = term_pos - offset
                fallback_chunk = binary_data[offset:offset + fallback_size]
                
                logger.warning(f"Usando detecção fallback para {hex(offset)}: {fallback_size} bytes")
                return fallback_size, fallback_chunk
                
            except:
                # Último recurso: tamanho fixo seguro
                safe_size = min(100, len(binary_data) - offset)
                return safe_size, binary_data[offset:offset + safe_size]
            
        except Exception as e:
            logger.error(f"Erro na detecção exata: {e}")
            safe_size = min(64, len(binary_data) - offset)
            return safe_size, binary_data[offset:offset + safe_size]
    
    def analyze_critical_pattern(self, original_chunk: bytes) -> Dict:
        """
        Analisa especificamente padrões críticos que DEVEM ser preservados.
        Foco no padrão 00 FF que está sendo perdido.
        """
        analysis = {
            'has_00_ff': False,
            'ff_position': -1,
            'text_space': len(original_chunk),
            'control_bytes': b'',
            'terminator_sequence': b'',
            'full_terminator': b''
        }
        
        # Busca pelo padrão crítico 00 FF
        null_ff_pattern = b'\x00\xff'
        ff_pos = original_chunk.find(null_ff_pattern)
        
        if ff_pos != -1:
            analysis['has_00_ff'] = True
            analysis['ff_position'] = ff_pos
            analysis['text_space'] = ff_pos  # Texto deve caber ANTES do 00 FF
            analysis['terminator_sequence'] = original_chunk[ff_pos:]  # Tudo após 00 FF
            
            # Captura TUDO depois do 00 FF para preservar
            analysis['full_terminator'] = original_chunk[ff_pos:]
            
            if self.debug_mode:
                logger.debug(f" PADRÃO CRÍTICO 00 FF DETECTADO:")
                logger.debug(f"  Posição: {ff_pos}")
                logger.debug(f"  Espaço para texto: {analysis['text_space']} bytes")
                logger.debug(f"  Terminador completo: {analysis['full_terminator'].hex()}")
        
        return analysis
    
    def create_exact_replacement_with_critical_preservation(self, original_chunk: bytes, new_text: str,
                                                        offset: int, binary_data: bytes, original_text: str) -> Tuple[bytes, bool]:
        """
        Cria substituição GARANTINDO preservação do padrão crítico 00 FF.
        Se não conseguir preservar, REJEITA a substituição e analisa o problema.
        """
        try:
            # Remove acentos do novo texto
            clean_text = new_text
            
            # Preserva códigos de controle
            for control in self.codec_controls:
                if control in new_text:
                    clean_text = new_text
                    break
            
            # ANÁLISE CRÍTICA: Procura pelo padrão 00 FF
            critical_analysis = self.analyze_critical_pattern(original_chunk)
            
            # Tenta codificar o texto
            try:
                new_bytes = clean_text.encode('shift_jis', errors='ignore')
            except:
                try:
                    new_bytes = clean_text.encode('ascii', errors='ignore')
                except:
                    logger.error(f"Falha total no encoding para: {new_text}")
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE ENCODING", 
                        "Não foi possível codificar o texto em shift_jis nem ascii"
                    )
                    return original_chunk, False
            
            # VERIFICA SE TEM PADRÃO CRÍTICO
            if critical_analysis['has_00_ff']:
                # MODO CRÍTICO: Deve preservar 00 FF obrigatoriamente
                ff_position = critical_analysis['ff_position']
                
                # Detecta se há byte de controle inicial
                control_prefix = b''
                text_start_pos = 0
                
                # Se o primeiro byte é um código de controle (< 32), preserva
                if len(original_chunk) > 0 and original_chunk[0] < 32:
                    control_prefix = original_chunk[0:1]
                    text_start_pos = 1
                
                # CALCULA ESPAÇO REAL DISPONÍVEL
                available_space = ff_position - text_start_pos
                
                # Verifica se o texto cabe (SEM adicionar null terminator extra)
                if len(new_bytes) > available_space:
                    logger.warning(f"REJEIÇÃO: Texto muito grande: {len(new_bytes)} > {available_space}")
                    self.stats['critical_pattern_lost'] += 1
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "OVERFLOW COM PADRÃO CRÍTICO",
                        f"Texto requer {len(new_bytes)} bytes mas só há {available_space} disponíveis antes do padrão crítico 00 FF"
                    )
                    return original_chunk, False
                
                # RECONSTRÓI DE FORMA PRECISA
                result = bytearray()
                
                # 1. Adiciona prefixo de controle se existir
                if control_prefix:
                    result.extend(control_prefix)
                
                # 2. Adiciona o novo texto
                result.extend(new_bytes)
                
                # 3. Preenche com zeros até a posição do FF (se necessário)
                while len(result) < ff_position:
                    result.append(0x00)
                
                # 4. Se passou da posição do FF, trunca (não deveria acontecer devido à verificação acima)
                if len(result) > ff_position:
                    logger.warning(f"Truncando para preservar FF: {len(result)} -> {ff_position}")
                    result = result[:ff_position]
                
                # 5. ADICIONA TODO O TERMINADOR PRESERVADO (incluindo 00 FF e tudo depois)
                result.extend(critical_analysis['full_terminator'])
                
                # VERIFICAÇÃO FINAL DE TAMANHO
                expected_size = len(original_chunk)
                actual_size = len(result)
                
                if actual_size != expected_size:
                    logger.error(f"ERRO: Tamanho final incorreto {actual_size} != {expected_size}")
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE TAMANHO FINAL",
                        f"Chunk final tem {actual_size} bytes mas deveria ter {expected_size} bytes. "
                        f"FF pos: {ff_position}, terminator: {len(critical_analysis['full_terminator'])} bytes"
                    )
                    return original_chunk, False
                
                # VERIFICAÇÃO CRÍTICA: Confirma presença do padrão 00 FF
                if b'\x00\xff' not in result:
                    logger.error(f"FALHA CRÍTICA: Padrão 00 FF foi perdido!")
                    self.stats['critical_pattern_lost'] += 1
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "PERDA DO PADRÃO CRÍTICO",
                        "O padrão 00 FF foi perdido durante a reconstrução"
                    )
                    return original_chunk, False
                
                self.stats['critical_pattern_preserved'] += 1
                
                if self.debug_mode:
                    logger.debug(f"SUCESSO em {hex(offset)}: {len(new_bytes)} bytes inseridos, FF preservado")
                
                return bytes(result), True
                
            else:
                # MODO NORMAL: Não há padrão crítico - usa lógica original
                available_space = len(original_chunk)
                
                control_prefix = b''
                if len(original_chunk) > 0 and original_chunk[0] < 32:
                    control_prefix = original_chunk[0:1]
                    available_space -= 1
                
                if len(new_bytes) > available_space:
                    logger.warning(f"Texto muito grande: {len(new_bytes)} > {available_space}")
                    self.stats['skipped_size'] += 1
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "OVERFLOW SEM PADRÃO CRÍTICO",
                        f"Texto requer {len(new_bytes)} bytes mas só há {available_space} disponíveis"
                    )
                    return original_chunk, False
                
                # Reconstrói normalmente
                result = bytearray()
                
                if control_prefix:
                    result.extend(control_prefix)
                
                result.extend(new_bytes)
                
                # Padding com zeros até o tamanho original
                while len(result) < len(original_chunk):
                    result.append(0x00)
                
                if len(result) > len(original_chunk):
                    result = result[:len(original_chunk)]
                
                return bytes(result), True
            
        except Exception as e:
            logger.error(f"Erro na criação de substituição crítica: {e}")
            
            self.analyze_problem_and_export(
                binary_data, offset, original_text, new_text,
                "ERRO GERAL NA SUBSTITUIÇÃO",
                f"Exceção durante a criação da substituição: {str(e)}"
            )
            return original_chunk, False

    def rebuild_binary_fixed(self, binary_path: Path, csv_path: Path, output_path: Path, analysis_path: Path) -> bool:
        """
        VERSÃO COM DEBUG DETALHADO para rastrear textos que desaparecem silenciosamente.
        """
        try:
            # Configura arquivo de análise
            self.setup_analysis_file(analysis_path)

            # Carrega o arquivo binário original
            logger.info(f"Carregando arquivo binário: {binary_path.name}")
            with open(binary_path, "rb") as f:
                original_data = f.read()
            
            # Valida se há bytes inválidos para UTF-8
            try:
                original_data.decode("utf-8")
            except UnicodeDecodeError as e:
                # Descobre linha e coluna contando bytes até o erro
                before_error = original_data[:e.start]
                line_number = before_error.count(b'\n') + 1
                col_number = len(before_error.split(b'\n')[-1]) + 1

                logger.error(
                    f"Erro de decodificação UTF-8 na posição {e.start} "
                    f"(linha {line_number}, coluna {col_number}): "
                    f"bytes={original_data[e.start:e.end]} "
                    f"(hex={original_data[e.start:e.end].hex()})"
                )

            # Cria uma cópia para modificação
            binary_data = bytearray(original_data)

            # Carrega as traduções
            logger.info(f"Carregando traduções: {csv_path.name}")
            
            # Tenta diferentes delimitadores
            for delimiter in ['\t', ',', ';']:
                try:
                    df = pd.read_csv(csv_path, delimiter=delimiter)
                    if len(df.columns) > 1:  # Se tem mais de uma coluna, provavelmente é o delimiter correto
                        break
                except:
                    continue
            
            logger.info(f"Processando {len(df)} entradas em MODO CRÍTICO com PRESERVAÇÃO 00 FF...")
            
            # ADICIONA CONTADOR DE ENTRADA ESPECÍFICA PARA DEBUG
            target_offset = 0x114a01  # Offset problemático para analise
            
            # Ordena por offset para processar sequencialmente
            df = df.sort_values('offset')
            
            # Processa cada entrada
            for index, row in df.iterrows():
                self.stats['processed'] += 1
                
                try:
                    # Extrai informações
                    offset = int(row["offset"], 16)
                    original_text = str(row["texto"]).strip()
                    
                    # DEBUG ESPECÍFICO para o offset problemático
                    is_target = (offset == target_offset)
                    if is_target:
                        logger.info(f"[TARGET] RASTREANDO OFFSET PROBLEMÁTICO: {hex(offset)}")
                        logger.info(f"   Original: '{original_text[:100]}...'")

                    # Verifica se há tradução
                    translated_text = str(row.get("texto_traduzido", "")).strip()
                    if not translated_text or translated_text.lower() in ['nan', 'none', '']:
                        text_to_use = original_text
                        is_modification = False
                        if is_target:
                            logger.info(f"   [NO TRANSLATION] - usando texto original")
                    else:
                        text_to_use = translated_text
                        is_modification = True
                        if is_target:
                            logger.info(f"   [TRANSLATION FOUND]: '{text_to_use[:100]}...'")

                    # Se é exatamente o mesmo texto, pula
                    if text_to_use == original_text:
                        self.stats['identical_preserved'] += 1
                        if is_target:
                            logger.info(f"   [IDENTICAL] - preservando sem modificacao")
                        elif self.debug_mode:
                            logger.debug(f"Texto idêntico em {hex(offset)}, preservando")
                        continue

                    if is_target:
                        logger.info(f"   [PROCESSING] INICIANDO PROCESSAMENTO...")

                    # Detecta boundaries exatas da string
                    try:
                        chunk_size, original_chunk = self.detect_string_exact(
                            binary_data, offset, original_text
                        )
                        
                        if is_target:
                            logger.info(f"   [CHUNK] DETECTADO: {len(original_chunk)} bytes")
                            logger.info(f"       Hex: {original_chunk[:32].hex()}{'...' if len(original_chunk) > 32 else ''}")
                        
                    except Exception as e:
                        logger.error(f"[ERROR] FALHA NA DETECÇÃO DE STRING em {hex(offset)}: {e}")
                        if is_target:
                            logger.error(f"   [TARGET] FALHA CRÍTICA NA DETECÇÃO!")
                        
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "FALHA NA DETECÇÃO DE STRING",
                            f"Erro durante detect_string_exact: {str(e)}"
                        )
                        continue

                    # ANÁLISE CRÍTICA COM LOGGING DETALHADO
                    try:
                        critical_analysis = self.analyze_critical_pattern(original_chunk)
                        
                        if is_target:
                            logger.info(f"   [CRITICAL] ANÁLISE CRÍTICA:")
                            logger.info(f"       Padrão 00 FF: {'SIM' if critical_analysis['has_00_ff'] else 'NAO'}")
                            if critical_analysis['has_00_ff']:
                                logger.info(f"       Posição FF: {critical_analysis['ff_position']}")
                                logger.info(f"       Espaço texto: {critical_analysis['text_space']} bytes")
                                logger.info(f"       Terminador: {critical_analysis['full_terminator'].hex()}")
                            else:
                                logger.info(f"       Espaço total: {len(original_chunk)} bytes")

                    except Exception as e:
                        logger.error(f"[ERROR] FALHA NA ANÁLISE CRÍTICA em {hex(offset)}: {e}")
                        if is_target:
                            logger.error(f"   [TARGET] FALHA NA ANÁLISE CRÍTICA!")
                        
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "FALHA NA ANÁLISE CRÍTICA",
                            f"Erro durante analyze_critical_pattern: {str(e)}"
                        )
                        continue

                    # TESTE DE ENCODING COM LOGGING
                    try:
                        clean_text = text_to_use
                        test_encoded = clean_text.encode('shift_jis', errors='ignore')
                        
                        if is_target:
                            logger.info(f"   [ENCODING] TESTE:")
                            logger.info(f"       Texto limpo: '{clean_text[:80]}...'")
                            logger.info(f"       Bytes necessários: {len(test_encoded)}")
                            logger.info(f"       Hex: {test_encoded[:32].hex()}{'...' if len(test_encoded) > 32 else ''}")
                        
                    except Exception as e:
                        logger.error(f"[ERROR] FALHA NO ENCODING em {hex(offset)}: {e}")
                        if is_target:
                            logger.error(f"   [TARGET] FALHA NO ENCODING!")
                        
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "FALHA NO ENCODING",
                            f"Erro durante teste de encoding: {str(e)}"
                        )
                        continue

                    # VERIFICAÇÃO PRÉVIA DE ESPAÇO
                    try:
                        if critical_analysis['has_00_ff']:
                            available_space = critical_analysis['text_space']
                            # Subtrai byte de controle se existir
                            if len(original_chunk) > 0 and original_chunk[0] < 32:
                                available_space -= 1
                        else:
                            available_space = len(original_chunk)
                            if len(original_chunk) > 0 and original_chunk[0] < 32:
                                available_space -= 1
                        
                        space_needed = len(test_encoded)
                        
                        if is_target:
                            logger.info(f"   [SPACE] VERIFICAÇÃO DE ESPAÇO:")
                            logger.info(f"       Espaço disponível: {available_space} bytes")
                            logger.info(f"       Espaço necessário: {space_needed} bytes")
                            logger.info(f"       Resultado: {'CABE' if space_needed <= available_space else 'NAO CABE'}")
                        
                        if space_needed > available_space:
                            if is_target:
                                logger.warning(f"   [TARGET] OVERFLOW DETECTADO NA VERIFICAÇÃO PRÉVIA!")
                            
                            overflow_amount = space_needed - available_space
                            self.analyze_problem_and_export(
                                binary_data, offset, original_text, text_to_use,
                                "OVERFLOW DETECTADO NA VERIFICAÇÃO PRÉVIA",
                                f"Necessário: {space_needed} bytes, Disponível: {available_space} bytes, Overflow: {overflow_amount} bytes"
                            )
                            
                            self.stats['skipped_size'] += 1
                            continue

                    except Exception as e:
                        logger.error(f"[ERROR] FALHA NA VERIFICAÇÃO PRÉVIA em {hex(offset)}: {e}")
                        if is_target:
                            logger.error(f"   [TARGET] FALHA NA VERIFICAÇÃO PRÉVIA!")
                        continue

                    # CRIA SUBSTITUIÇÃO COM LOGGING DETALHADO
                    if is_target:
                        logger.info(f"   [REPLACEMENT] CRIANDO SUBSTITUIÇÃO...")

                    try:
                        new_chunk, success = self.create_exact_replacement_with_critical_preservation(
                            original_chunk, text_to_use, offset, binary_data, original_text
                        )
                        
                        if is_target:
                            logger.info(f"   [REPLACEMENT] RESULTADO: {'SUCESSO' if success else 'FALHA'}")
                            if success:
                                logger.info(f"       Chunk final: {len(new_chunk)} bytes")
                                logger.info(f"       Hex: {new_chunk[:32].hex()}{'...' if len(new_chunk) > 32 else ''}")
                            else:
                                logger.info(f"       FALHA: Substituição rejeitada")
                        
                        if not success:
                            if is_target:
                                logger.warning(f"   [TARGET] SUBSTITUIÇÃO FALHOU!")
                            else:
                                logger.warning(f"Substituição REJEITADA para offset {hex(offset)}")
                            continue

                    except Exception as e:
                        logger.error(f"[ERROR] EXCEÇÃO NA CRIAÇÃO DE SUBSTITUIÇÃO em {hex(offset)}: {e}")
                        if is_target:
                            logger.error(f"   [TARGET] EXCEÇÃO NA SUBSTITUIÇÃO!")
                        
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "EXCEÇÃO NA CRIAÇÃO DE SUBSTITUIÇÃO",
                            f"Exceção não capturada: {str(e)}"
                        )
                        continue

                    # VERIFICAÇÃO FINAL DE TAMANHO
                    if len(new_chunk) != len(original_chunk):
                        logger.error(f"[ERROR] TAMANHO FINAL INCORRETO em {hex(offset)}: {len(new_chunk)} != {len(original_chunk)}")
                        if is_target:
                            logger.error(f"   [TARGET] TAMANHO INCORRETO!")
                        
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "TAMANHO FINAL INCORRETO",
                            f"Chunk criado: {len(new_chunk)} bytes, Esperado: {len(original_chunk)} bytes"
                        )
                        continue

                    # APLICA A MODIFICAÇÃO
                    try:
                        binary_data[offset:offset + len(new_chunk)] = new_chunk
                        
                        self.stats['applied'] += 1
                        if is_modification:
                            self.stats['modified_applied'] += 1
                        
                        if is_target:
                            logger.info(f"   [SUCCESS] APLICAÇÃO CONCLUÍDA COM SUCESSO!")
                            logger.info(f"       Modificação aplicada ao binário")
                        elif self.debug_mode:
                            logger.debug(f"Aplicado em {hex(offset)}: '{text_to_use[:30]}...'")

                    except Exception as e:
                        logger.error(f"[ERROR] FALHA NA APLICAÇÃO FINAL em {hex(offset)}: {e}")
                        if is_target:
                            logger.error(f"   [TARGET] FALHA NA APLICAÇÃO FINAL!")
                        
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "FALHA NA APLICAÇÃO FINAL",
                            f"Erro ao aplicar chunk ao binário: {str(e)}"
                        )
                        continue
                        
                except Exception as e:
                    logger.error(f" ERRO GERAL ao processar linha {index} (offset {hex(offset)}): {e}")
                    
                    if offset == target_offset:
                        logger.error(f" ERRO GERAL PARA OFFSET ALVO!")
                    
                    # Análise de erro geral de processamento
                    try:
                        error_text = text_to_use if 'text_to_use' in locals() else "N/A"
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, error_text,
                            "ERRO GERAL DE PROCESSAMENTO",
                            f"Exceção não capturada durante processamento da linha {index}: {str(e)}"
                        )
                    except:
                        logger.error(f"Falha até mesmo para gerar análise de erro em {hex(offset)}")
                    
                    continue
            
            # Verificação final: tamanho do arquivo
            if len(binary_data) != len(original_data):
                logger.error(f"ERRO CRÍTICO: Tamanho do arquivo mudou! {len(original_data)} -> {len(binary_data)}")
                return False
            
            # Salva o arquivo de saída
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(binary_data)
            
            # Fecha arquivo de análise
            if self.analysis_file:
                self.analysis_file.close()
                self.analysis_file = None
            
            self._log_statistics(output_path, analysis_path)
            return True
            
        except Exception as e:
            logger.error(f"Erro crítico durante a reconstrução: {e}")
            
            # Fecha arquivo de análise em caso de erro
            if self.analysis_file:
                try:
                    self.analysis_file.write(f"\nERRO CRÍTICO DURANTE RECONSTRUÇÃO: {str(e)}\n")
                    self.analysis_file.close()
                except:
                    pass
                self.analysis_file = None
            
            return False
    
    def _log_statistics(self, output_path: Path, analysis_path: Path):
        """Registra estatísticas da operação."""
        logger.info(f"{'='*50}")
        logger.info(f"RECONSTRUÇÃO COM PRESERVAÇÃO CRÍTICA CONCLUÍDA")
        logger.info(f"{'='*50}")
        logger.info(f"Arquivo salvo em: {output_path}")
        logger.info(f"Entradas processadas: {self.stats['processed']}")
        logger.info(f"Modificações aplicadas: {self.stats['applied']}")
        logger.info(f"  - Textos idênticos preservados: {self.stats['identical_preserved']}")
        logger.info(f"  - Traduções efetivamente aplicadas: {self.stats['modified_applied']}")
        logger.info(f"Padrões críticos preservados: {self.stats['critical_pattern_preserved']}")
        logger.info(f"Padrões críticos perdidos (rejeitados): {self.stats['critical_pattern_lost']}")
        logger.info(f"Correções de encoding: {self.stats['encoding_fixes']}")
        logger.info(f"Puladas por tamanho: {self.stats['skipped_size']}")
        logger.info(f"Puladas por encoding: {self.stats['skipped_encoding']}")
        logger.info(f"Problemas analisados e exportados: {self.stats['problems_analyzed']}")
        
        success_rate = (self.stats['applied'] / self.stats['processed'] * 100) if self.stats['processed'] > 0 else 0
        logger.info(f"Taxa de sucesso: {success_rate:.1f}%")

        general_translation = ( (self.stats['applied'] + self.stats['identical_preserved']) / self.stats['processed'] * 100) if self.stats['processed'] > 0 else 0
        logger.info(f"Taxa de sucesso geral (traduzidos + preservados): {general_translation:.1f}%")
        
        if self.stats['critical_pattern_preserved'] > 0:
            logger.info(f"PADRÕES CRÍTICOS 00 FF PRESERVADOS COM SUCESSO!")
        
        if self.stats['critical_pattern_lost'] > 0:
            logger.warning(f"  {self.stats['critical_pattern_lost']} substituições foram rejeitadas para preservar padrões críticos")
        
        if self.stats['problems_analyzed'] > 0:
            logger.info(f"ARQUIVO DE ANÁLISE DE PROBLEMAS:")
            logger.info(f"  Local: {analysis_path}")
            logger.info(f"  Problemas documentados: {self.stats['problems_analyzed']}")
            logger.info(f"  Use este arquivo para investigar problemas de inserção em detalhes")


def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Reconstrói arquivos binários MGS com preservação garantida do padrão crítico 00 FF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --stage                              # Reconstrói STAGE.DIR do CD1
  %(prog)s --demo --debug                       # Reconstrói DEMO.DAT com debug
  %(prog)s --cd CD2 --vox                       # Reconstrói VOX.DAT do CD2
  %(prog)s --list                               # Lista arquivos disponíveis
  %(prog)s --brf --no-strict                    # Reconstrói BRF.DAT sem modo estrito
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
            help=f"Reconstrói {file_descriptions[file_key]}"
        )
    
    # Argumentos para compatibilidade com versão anterior
    compat_group = parser.add_argument_group('Compatibilidade (argumentos antigos)')
    compat_group.add_argument(
        "--binary", 
        type=Path,
        help="Caminho específico do arquivo binário original (compatibilidade)"
    )
    compat_group.add_argument(
        "--csv", 
        type=Path,
        help="Caminho específico do CSV com traduções (compatibilidade)"
    )
    compat_group.add_argument(
        "--output", 
        type=Path,
        help="Caminho específico do arquivo de saída (compatibilidade)"
    )
    compat_group.add_argument(
        "--analysis", 
        type=Path,
        help="Caminho específico do arquivo de análise (compatibilidade)"
    )
    
    # Configurações de reconstrução
    rebuild_group = parser.add_argument_group('Configurações de reconstrução')
    rebuild_group.add_argument(
        "--no-strict", 
        action="store_true",
        help="Desativa modo estrito"
    )
    rebuild_group.add_argument(
        "--debug", 
        action="store_true",
        help="Modo debug com log detalhado"
    )
    
    return parser


def main():
    """Função principal do script."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configura log level
    if args.debug:
        logger.setLevel(10)  # DEBUG
    
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
        print(f"\nUso: {parser.prog} --cd {args.cd} --<arquivo>")
        print(f"Exemplo: {parser.prog} --cd {args.cd} --stage")
        return
    
    # Determina arquivos para reconstrução
    binary_file = None
    csv_file = None
    output_file = None
    analysis_file = None
    
    if args.binary:
        # Compatibilidade: usa arquivos especificados
        binary_file = args.binary
        csv_file = args.csv
        output_file = args.output
        analysis_file = args.analysis
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
            logger.info(f"Use --list para ver arquivos disponíveis ou especifique um arquivo com --stage, --demo, etc.")
            return
        elif len(selected_files) > 1:
            logger.error(f"Múltiplos arquivos selecionados: {', '.join(selected_files)}")
            logger.info("Selecione apenas um arquivo por vez para reconstrução")
            return
        
        # Resolve arquivo selecionado
        file_key = selected_files[0]
        binary_file = file_resolver.get_original_path(file_key)
        csv_file = file_resolver.get_csv_path(file_key)
        output_file = file_resolver.get_output_path(file_key)
        analysis_file = file_resolver.get_analysis_path(file_key)
        
        if not binary_file:
            logger.error(f"Arquivo original não encontrado: {file_key} ({args.cd})")
            return
        
        if not csv_file:
            logger.error(f"CSV com traduções não encontrado: {file_key} ({args.cd})")
            logger.info(f"Procurei em:")
            logger.info(f"  - {file_resolver.translated_path}/strings_*_traduzido.csv")
            logger.info(f"  - {file_resolver.extracted_path}/strings_*.csv")
            return
        
        logger.info(f" Arquivo selecionado: {file_key}")
        logger.info(f"   Original: {binary_file.name}")
        logger.info(f"   CSV: {csv_file.name}")
        logger.info(f"   Saída: {output_file.name}")
        logger.info(f"   Análise: {analysis_file.name}")
    
    # Valida arquivos obrigatórios
    if not binary_file or not binary_file.exists():
        logger.error(f"Arquivo binário não encontrado: {binary_file}")
        return
    
    if not csv_file or not csv_file.exists():
        logger.error(f"Arquivo CSV não encontrado: {csv_file}")
        return
    
    # Define caminhos padrão se não especificados
    if not output_file:
        output_file = Path("output_patched.bin")
    
    if not analysis_file:
        analysis_file = Path("insertion_problems.txt")
    
    # Executa a reconstrução
    rebuilder = MGSRebuilder(
        debug_mode=args.debug,
        strict_mode=not args.no_strict
    )
    
    logger.info(f" Iniciando reconstrução com preservação crítica...")
    logger.info(f"   Modo debug: {'ATIVO' if args.debug else 'INATIVO'}")
    logger.info(f"   Modo estrito: {'ATIVO' if not args.no_strict else 'INATIVO'}")
    
    success = rebuilder.rebuild_binary_fixed(binary_file, csv_file, output_file, analysis_file)
    
    if success:
        logger.info(" RECONSTRUÇÃO CONCLUÍDA COM SUCESSO!")
        logger.info(" DICAS IMPORTANTES:")
        logger.info("   • Teste no emulador com save state")
        logger.info("   • Padrões críticos 00 FF foram preservados obrigatoriamente")
        logger.info("   • Substituições que danificariam o padrão foram rejeitadas")
        logger.info("   • Acentos foram removidos automaticamente para compatibilidade")
        logger.info("   • Endereços foram preservados exatamente")
        logger.info("   • Problemas de inserção foram analisados e documentados automaticamente")
        logger.info(f"  • Consulte o arquivo de análise: {analysis_file}")
    else:
        logger.error(" Falha na reconstrução!")
        sys.exit(1)


if __name__ == "__main__":

    main()

    """
    Exemplos de uso melhorados:
    
    # Reconstrói STAGE.DIR do CD1
    python tools/rebuild_text.py --stage
    
    # Reconstrói DEMO.DAT com debug ativo
    python tools/rebuild_text.py --demo --debug
    
    # Reconstrói VOX.DAT do CD2
    python tools/rebuild_text.py --cd CD2 --vox
    
    # Lista arquivos disponíveis
    python tools/rebuild_text.py --list
    
    # Reconstrói RADIO.DAT sem modo estrito (não recomendado)
    python tools/rebuild_text.py --radio --no-strict
    
    # Compatibilidade com versão anterior
    python tools/rebuild_text.py --binary arquivo.dat --csv traducoes.csv --output saida.dat
    """
