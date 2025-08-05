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

# Adiciona o diretório raiz ao sys.path para permitir importações internas
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

# Inicializa o logger para registrar as operações do script
logger = setup_logger()

# Caminhos padrão para os arquivos
DEFAULT_PATHS = {
    'original': BASE_DIR / "assets" / "fontes" / "CD1" / "RADIO.DAT",
    'csv': BASE_DIR / "translated" / "strings_RADIO_traduzido.csv",
    'output': BASE_DIR / "patches" / "RADIO_PATCHED.DAT",
    'analysis': BASE_DIR / "output" / "insertion_problems.txt"
}

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
                clean_translated = self.remove_accents_safe(translated_text)
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
                logger.info(f"🔍 ANÁLISE DETALHADA DE PROBLEMA - DEBUG MODE")
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
                        
                    clean_translated = self.remove_accents_safe(translated_text)
                    translated_bytes = clean_translated.encode('shift_jis', errors='ignore')
                    logger.info(f"NECESSÁRIO: {len(translated_bytes)} bytes")
                    
                except:
                    logger.info(f"ESPAÇO: Erro na análise")
                
                logger.info(f"{'='*60}")
                logger.info(f"📁 Análise completa salva em: {self.analysis_file.name}")
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

    def remove_accents_safe(self, text: str) -> str:
        """
        Remove acentos de forma segura para compatibilidade com Shift-JIS.
        """
        try:
            # Primeiro, aplica o mapeamento manual
            result = text
            for accented, replacement in self.accent_map.items():
                result = result.replace(accented, replacement)
            
            # Depois, usa unicodedata para casos não cobertos
            normalized = unicodedata.normalize('NFD', result)
            ascii_text = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')
            
            # Verifica se consegue codificar em Shift-JIS
            try:
                ascii_text.encode('shift_jis')
                self.stats['encoding_fixes'] += 1
                return ascii_text
            except UnicodeEncodeError:
                # Se ainda não conseguir, força ASCII puro
                ascii_only = ''.join(c if ord(c) < 128 else '?' for c in ascii_text)
                logger.warning(f"Forçando ASCII puro para: '{text}' -> '{ascii_only}'")
                return ascii_only
                
        except Exception as e:
            logger.error(f"Erro na remoção de acentos: {e}")
            # Fallback: ASCII puro
            return ''.join(c if ord(c) < 128 else '?' for c in text)
    
    def detect_string_exact(self, binary_data: bytes, offset: int, expected_text: str) -> Tuple[int, bytes]:
        """
        Detecta com MÁXIMA precisão onde uma string termina no arquivo original.
        """
        try:
            # Primeiro, limpa o texto esperado
            clean_expected = self.remove_accents_safe(expected_text)
            
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
            clean_text = self.remove_accents_safe(new_text)
            
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
                    # Analisa o problema de encoding
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE ENCODING", 
                        "Não foi possível codificar o texto em shift_jis nem ascii"
                    )
                    return original_chunk, False
            
            # VERIFICA SE TEM PADRÃO CRÍTICO
            if critical_analysis['has_00_ff']:
                # MODO CRÍTICO: Deve preservar 00 FF obrigatoriamente
                text_space = critical_analysis['text_space']
                
                # Considera byte de controle inicial (como 08)
                control_byte = b''
                if len(original_chunk) > 0 and original_chunk[0] < 32:
                    control_byte = original_chunk[0:1]
                    text_space = max(0, text_space - 1)
                
                # Verifica se o texto cabe no espaço disponível
                min_space_needed = len(new_bytes) + 1  # +1 para null terminator antes do FF
                
                if text_space < min_space_needed:
                    logger.warning(f"REJEIÇÃO: Texto muito grande para preservar 00 FF: {min_space_needed} > {text_space}")
                    self.stats['critical_pattern_lost'] += 1
                    
                    # Analisa o problema de tamanho com padrão crítico
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "OVERFLOW COM PADRÃO CRÍTICO",
                        f"Texto requer {min_space_needed} bytes mas só há {text_space} disponíveis antes do padrão crítico 00 FF"
                    )
                    return original_chunk, False
                
                # RECONSTRÓI PRESERVANDO 00 FF OBRIGATORIAMENTE
                result = bytearray()
                
                # Adiciona byte de controle se existir
                if control_byte:
                    result.extend(control_byte)
                
                # Adiciona o novo texto
                result.extend(new_bytes)
                
                # Calcula padding necessário até o 00 FF
                current_size = len(result)
                target_size = len(control_byte) + critical_analysis['ff_position']
                
                if current_size < target_size:
                    # Adiciona null padding até a posição do FF
                    padding_needed = target_size - current_size
                    result.extend(b'\x00' * padding_needed)
                elif current_size > target_size:
                    # Texto muito grande - trunca
                    logger.warning(f"Truncando texto para preservar 00 FF")
                    result = result[:target_size]
                
                # ADICIONA O TERMINADOR COMPLETO (incluindo 00 FF)
                result.extend(critical_analysis['full_terminator'])
                
                # VERIFICA TAMANHO FINAL
                if len(result) != len(original_chunk):
                    logger.error(f"ERRO CRÍTICO: Tamanho final incorreto {len(result)} != {len(original_chunk)}")
                    
                    # Analisa problema de tamanho final
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE TAMANHO FINAL",
                        f"Chunk final tem {len(result)} bytes mas deveria ter {len(original_chunk)} bytes"
                    )
                    return original_chunk, False
                
                # VERIFICAÇÃO FINAL: Confirma que 00 FF está presente
                if b'\x00\xff' not in result:
                    logger.error(f"FALHA CRÍTICA: Padrão 00 FF foi perdido durante a reconstrução!")
                    self.stats['critical_pattern_lost'] += 1
                    
                    # Analisa perda do padrão crítico
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "PERDA DO PADRÃO CRÍTICO",
                        "O padrão 00 FF foi perdido durante a reconstrução apesar das verificações"
                    )
                    return original_chunk, False
                
                self.stats['critical_pattern_preserved'] += 1
                return bytes(result), True
                
            else:
                # MODO NORMAL: Não há padrão crítico
                available_space = len(original_chunk)
                
                # Considera byte de controle inicial
                control_byte = b''
                if len(original_chunk) > 0 and original_chunk[0] < 32:
                    control_byte = original_chunk[0:1]
                    available_space -= 1
                
                # Verifica se cabe
                if len(new_bytes) > available_space:
                    logger.warning(f"Texto muito grande: {len(new_bytes)} > {available_space}")
                    self.stats['skipped_size'] += 1
                    
                    # Analisa problema de tamanho normal
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "OVERFLOW SEM PADRÃO CRÍTICO",
                        f"Texto requer {len(new_bytes)} bytes mas só há {available_space} disponíveis"
                    )
                    return original_chunk, False
                
                # Reconstrói normalmente
                result = bytearray()
                
                if control_byte:
                    result.extend(control_byte)
                
                result.extend(new_bytes)
                
                # Padding com zeros até o tamanho original
                while len(result) < len(original_chunk):
                    result.append(0x00)
                
                if len(result) > len(original_chunk):
                    result = result[:len(original_chunk)]
                
                return bytes(result), True
            
        except Exception as e:
            logger.error(f"Erro na criação de substituição crítica: {e}")
            
            # Analisa erro geral
            self.analyze_problem_and_export(
                binary_data, offset, original_text, new_text,
                "ERRO GERAL NA SUBSTITUIÇÃO",
                f"Exceção durante a criação da substituição: {str(e)}"
            )
            return original_chunk, False

    def rebuild_binary_fixed(self, binary_path: Path, csv_path: Path, output_path: Path, analysis_path: Path) -> bool:
        """
        Reconstrói o binário com GARANTIA de preservação do padrão crítico 00 FF.
        """
        try:
            # Configura arquivo de análise
            self.setup_analysis_file(analysis_path)

            # Carrega o arquivo binário original
            logger.info(f"Carregando arquivo binário: {binary_path}")
            with open(binary_path, "rb") as f:
                original_data = f.read()
            
            # Cria uma cópia para modificação
            binary_data = bytearray(original_data)
            
            # Carrega as traduções
            logger.info(f"Carregando traduções: {csv_path}")
            df = pd.read_csv(csv_path, delimiter="\t")
            
            logger.info(f"Processando {len(df)} entradas em MODO CRÍTICO (preservação garantida de 00 FF)...")
            
            # Ordena por offset para processar sequencialmente
            df = df.sort_values('offset')
            
            # Processa cada entrada
            for index, row in df.iterrows():
                self.stats['processed'] += 1
                
                try:
                    # Extrai informações
                    offset = int(row["offset"], 16)
                    original_text = str(row["texto"]).strip()
                    
                    # Verifica se há tradução
                    translated_text = str(row.get("texto_traduzido", "")).strip()
                    if not translated_text or translated_text.lower() in ['nan', 'none', '']:
                        text_to_use = original_text
                        is_modification = False
                    else:
                        text_to_use = translated_text
                        is_modification = True
                    
                    # Se é exatamente o mesmo texto, pula
                    if text_to_use == original_text:
                        self.stats['identical_preserved'] += 1
                        if self.debug_mode:
                            logger.debug(f"Texto idêntico em {hex(offset)}, preservando")
                        continue
                    
                    # Detecta boundaries exatas da string
                    chunk_size, original_chunk = self.detect_string_exact(
                        binary_data, offset, original_text
                    )
                    
                    # CRIA SUBSTITUIÇÃO COM PRESERVAÇÃO CRÍTICA GARANTIDA E ANÁLISE DE PROBLEMAS
                    new_chunk, success = self.create_exact_replacement_with_critical_preservation(
                        original_chunk, text_to_use, offset, binary_data, original_text
                    )
                    
                    if not success:
                        logger.warning(f"Substituição REJEITADA para offset {hex(offset)} (problema analisado e exportado)")
                        continue
                    
                    # Aplica a mudança - PRESERVANDO TAMANHO EXATO
                    if len(new_chunk) != len(original_chunk):
                        logger.error(f"ERRO CRÍTICO: Tamanhos não coincidem em {hex(offset)}")
                        
                        # Analisa problema de tamanho inconsistente
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "TAMANHO INCONSISTENTE APÓS CRIAÇÃO",
                            f"Chunk criado tem {len(new_chunk)} bytes mas deveria ter {len(original_chunk)} bytes"
                        )
                        continue
                    
                    binary_data[offset:offset + len(new_chunk)] = new_chunk
                    
                    self.stats['applied'] += 1
                    if is_modification:
                        self.stats['modified_applied'] += 1
                    
                    if self.debug_mode:
                        logger.debug(f"Aplicado em {hex(offset)}: '{text_to_use[:30]}...'")
                        
                except Exception as e:
                    logger.error(f"Erro ao processar linha {index} (offset {hex(offset)}): {e}")
                    
                    # Analisa erro geral de processamento
                    try:
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use if 'text_to_use' in locals() else "N/A",
                            "ERRO DE PROCESSAMENTO",
                            f"Exceção durante processamento da linha {index}: {str(e)}"
                        )
                    except:
                        pass  # Evita erro em cascata
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
        
        if self.stats['critical_pattern_preserved'] > 0:
            logger.info(f"PADRÕES CRÍTICOS 00 FF PRESERVADOS COM SUCESSO!")
        
        if self.stats['critical_pattern_lost'] > 0:
            logger.warning(f"  {self.stats['critical_pattern_lost']} substituições foram rejeitadas para preservar padrões críticos")
        
        if self.stats['problems_analyzed'] > 0:
            logger.info(f"ARQUIVO DE ANÁLISE DE PROBLEMAS:")
            logger.info(f"  Local: {analysis_path}")
            logger.info(f"  Problemas documentados: {self.stats['problems_analyzed']}")
            logger.info(f"  Use este arquivo para investigar problemas de inserção em detalhes")


def main():
    """Função principal do script."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Reconstrói arquivos binários MGS com preservação garantida do padrão crítico 00 FF e análise automática de problemas")
    parser.add_argument("--binary", type=Path, default=DEFAULT_PATHS['original'],
                       help="Arquivo binário original")
    parser.add_argument("--csv", type=Path, default=DEFAULT_PATHS['csv'], 
                       help="Arquivo CSV com traduções")
    parser.add_argument("--output", type=Path, default=DEFAULT_PATHS['output'],
                       help="Arquivo de saída")
    parser.add_argument("--analysis", type=Path, default=DEFAULT_PATHS['analysis'],
                       help="Arquivo de análise de problemas")
    parser.add_argument("--no-strict", action="store_true",
                       help="Desativa modo estrito")
    parser.add_argument("--debug", action="store_true",
                       help="Modo debug com log detalhado")
    
    args = parser.parse_args()
    
    # Configura log level
    if args.debug:
        logger.setLevel(10)  # DEBUG
    
    # Valida arquivos de entrada
    if not args.binary.exists():
        logger.error(f"Arquivo binário não encontrado: {args.binary}")
        sys.exit(1)
    
    if not args.csv.exists():
        logger.error(f"Arquivo CSV não encontrado: {args.csv}")
        sys.exit(1)
    
    # Executa a reconstrução
    rebuilder = MGSRebuilder(
        debug_mode=args.debug,
        strict_mode=not args.no_strict
    )
    
    success = rebuilder.rebuild_binary_fixed(args.binary, args.csv, args.output, args.analysis)
    
    if success:
        logger.info("RECONSTRUÇÃO CONCLUÍDA COM SUCESSO!")
        logger.info("DICAS IMPORTANTES:")
        logger.info("   • Teste no emulador com save state")
        logger.info("   • Padrões críticos 00 FF foram preservados obrigatoriamente")
        logger.info("   • Substituições que danificariam o padrão foram rejeitadas")
        logger.info("   • Acentos foram removidos automaticamente para compatibilidade")
        logger.info("   • Endereços foram preservados exatamente")
        logger.info("   • Problemas de inserção foram analisados e documentados automaticamente")
        logger.info(f"  • Consulte o arquivo de análise: {args.analysis}")
    else:
        logger.error("Falha na reconstrução!")
        sys.exit(1)


if __name__ == "__main__":
    main()