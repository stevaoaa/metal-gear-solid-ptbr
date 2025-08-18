#!/usr/bin/env python3
"""
Script unificado para reconstruir arquivos binários com textos traduzidos - MGS PSX.
Versão que combina as estratégias otimizadas para diferentes tipos de arquivo.
"""

import os
import sys
import pandas as pd
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from datetime import datetime
import argparse

# Adiciona o diretório raiz ao sys.path para permitir importações internas
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

# Inicializa o logger para registrar as operações do script
logger = setup_logger()

# Mapeamento de arquivos disponíveis por CD
FILE_MAPPING = {
    "CD1": {
        "radio": "RADIO.DAT",
        "stage": "STAGE.DIR",
        "demo": "DEMO.DAT",
        "vox": "VOX.DAT",
        "zmovie": "ZMOVIE.STR"
    },
    "CD2": {
        "radio": "RADIO.DAT",
        "stage": "STAGE.DIR",
        "demo": "DEMO.DAT",
        "vox": "VOX.DAT",
        "zmovie": "ZMOVIE.STR"
    }
}

# Configuração de estratégias por tipo de arquivo
FILE_STRATEGIES = {
    "STAGE.DIR": "stage_strategy",    # Usa estratégia avançada para STAGE
    "RADIO.DAT": "generic_strategy",  # Usa estratégia genérica
    "DEMO.DAT": "generic_strategy",   # Usa estratégia genérica
    "VOX.DAT": "generic_strategy",    # Usa estratégia genérica
    "ZMOVIE.STR": "generic_strategy"  # Usa estratégia genérica
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
            
            # Identifica estratégia
            strategy = FILE_STRATEGIES.get(filename, "generic_strategy")
            strategy_info = f"[{strategy.upper().replace('_', ' ')}]"
            
            status_info = f"Orig:{original_status} CSV:{csv_status} {strategy_info}"
            available_files.append(f"--{key:<8} {filename:<15} {size:<8} {status_info}")
            
            if csv_info:
                available_files.append(f"{'':>10} {csv_info}")
            if output_info:
                available_files.append(f"{'':>10} {output_info}")
            available_files.append("")  # Linha em branco para separar
        
        return available_files

class MGSRebuilderUnified:
    """
    Rebuilder unificado que aplica estratégias específicas por tipo de arquivo.
    """
    
    def __init__(self, debug_mode: bool = False, strict_mode: bool = True):
        self.debug_mode = debug_mode
        self.strict_mode = strict_mode
        self.analysis_file = None
        self.current_strategy = None
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
            'problems_analyzed': 0,
            'strategy_used': None
        }
        
        # Tabela de substituição para acentos
        self.accent_map = {
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
            'ç': 'c', 'Ç': 'C', 'ñ': 'n', 'Ñ': 'N',
            '"': '"', '"': '"', ''': "'", ''': "'",
            '–': '-', '—': '-', '…': '...',
        }
        
        # Códigos de controle do codec
        self.codec_controls = ['#N', '#P', '#W', '#C', '#K', '#E', '#S', '#T']
    
    def determine_strategy(self, file_path: Path) -> str:
        """Determina qual estratégia usar baseada no nome do arquivo."""
        filename = file_path.name.upper()
        strategy = FILE_STRATEGIES.get(filename, "generic_strategy")
        
        logger.info(f"Arquivo detectado: {filename}")
        logger.info(f"Estratégia selecionada: {strategy.upper().replace('_', ' ')}")
        
        if strategy == "stage_strategy":
            logger.info("  • Usa detecção avançada de sequências de controle múltiplas")
            logger.info("  • Otimizada para preservação de estruturas complexas")
        else:
            logger.info("  • Usa estratégia genérica com foco no padrão crítico 00 FF")
            logger.info("  • Otimizada para compatibilidade máxima")
        
        return strategy
    
    def setup_analysis_file(self, analysis_path: Path):
        """Configura o arquivo de análise de problemas."""
        try:
            analysis_path.parent.mkdir(parents=True, exist_ok=True)
            self.analysis_file = open(analysis_path, 'w', encoding='utf-8')
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.analysis_file.write(f"ANÁLISE DE PROBLEMAS - MGS PSX REBUILDER UNIFICADO\n")
            self.analysis_file.write(f"Gerado em: {timestamp}\n")
            self.analysis_file.write(f"Estratégia utilizada: {self.current_strategy}\n")
            self.analysis_file.write(f"{'='*80}\n\n")
            
            logger.info(f"Arquivo de análise configurado: {analysis_path}")
            
        except Exception as e:
            logger.error(f"Erro ao configurar arquivo de análise: {e}")
            self.analysis_file = None
    
    def analyze_problem_and_export(self, binary_data: bytes, offset: int, original_text: str, 
                                  translated_text: str, problem_type: str, details: str = ""):
        """Análise detalhada do problema e exportação para arquivo."""
        if not self.analysis_file:
            return
            
        try:
            self.stats['problems_analyzed'] += 1
            context_size = 100
            
            # Conteúdo da análise
            analysis_content = []
            analysis_content.append(f"PROBLEMA #{self.stats['problems_analyzed']:03d} - {problem_type}")
            analysis_content.append(f"{'='*50}")
            analysis_content.append(f"Estratégia: {self.current_strategy}")
            analysis_content.append(f"Offset: {hex(offset)}")
            analysis_content.append(f"Texto original:  '{original_text}'")
            analysis_content.append(f"Texto traduzido: '{translated_text}'")
            analysis_content.append(f"Detalhes: {details}")
            analysis_content.append("")
            
            # Contexto binário
            start = max(0, offset - context_size)
            end = min(len(binary_data), offset + context_size)
            context = binary_data[start:end]
            
            analysis_content.append(f"CONTEXTO BINÁRIO ({hex(start)} - {hex(end)}):")
            analysis_content.append(f"{'-'*60}")
            
            for i in range(0, min(len(context), 128), 16):
                chunk = context[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                addr = start + i
                marker = " <-- OFFSET" if start + i <= offset < start + i + 16 else ""
                analysis_content.append(f"{addr:08x}: {hex_part:<48} |{ascii_part}|{marker}")
            
            analysis_content.append("")
            
            # Tentativas de decodificação
            analysis_content.append(f"TENTATIVAS DE DECODIFICAÇÃO:")
            analysis_content.append(f"{'-'*30}")
            
            offset_in_context = offset - start
            sample_data = context[offset_in_context:offset_in_context+100]
            
            for encoding in ['shift_jis', 'ascii', 'latin-1', 'utf-8']:
                try:
                    decoded = sample_data.decode(encoding, errors='ignore')
                    clean_decoded = ''.join(c if ord(c) >= 32 else f'\\x{ord(c):02x}' for c in decoded[:50])
                    if clean_decoded.strip():
                        analysis_content.append(f"{encoding:>10}: '{clean_decoded}'")
                except Exception as e:
                    analysis_content.append(f"{encoding:>10}: ERRO - {str(e)}")
            
            # Análise específica por estratégia
            if self.current_strategy == "stage_strategy":
                self._analyze_stage_specific(analysis_content, binary_data, offset, original_text)
            else:
                self._analyze_generic_specific(analysis_content, binary_data, offset, original_text)
            
            analysis_content.append(f"{'='*80}")
            analysis_content.append("")
            
            # Escreve no arquivo
            for line in analysis_content:
                self.analysis_file.write(line + "\n")
            self.analysis_file.flush()
            
            # Debug no terminal se ativo
            if self.debug_mode:
                logger.info(f"\n{'='*60}")
                logger.info(f" ANÁLISE DETALHADA - {self.current_strategy.upper()}")
                logger.info(f"{'='*60}")
                logger.info(f"PROBLEMA #{self.stats['problems_analyzed']:03d}: {problem_type}")
                logger.info(f"Offset: {hex(offset)}")
                logger.info(f"Original:  '{original_text[:40]}{'...' if len(original_text) > 40 else ''}'")
                logger.info(f"Traduzido: '{translated_text[:40]}{'...' if len(translated_text) > 40 else ''}'")
                logger.info(f"Detalhes: {details}")
                logger.info(f"{'='*60}\n")
            
        except Exception as e:
            logger.error(f"Erro durante análise: {e}")
    
    def _analyze_stage_specific(self, analysis_content: List[str], binary_data: bytes, offset: int, original_text: str):
        """Análise específica para arquivos STAGE."""
        analysis_content.append(f"ANÁLISE ESPECÍFICA PARA STAGE:")
        analysis_content.append(f"{'-'*35}")
        
        # Detecta sequências de controle múltiplas
        control_sequence_length = 0
        scan_pos = 0
        max_control_scan = min(5, len(binary_data) - offset)
        
        while (scan_pos < max_control_scan and 
               offset + scan_pos < len(binary_data) and
               binary_data[offset + scan_pos] < 32):
            control_sequence_length += 1
            scan_pos += 1
        
        if control_sequence_length > 0:
            control_seq = binary_data[offset:offset + control_sequence_length]
            analysis_content.append(f"Sequência de controle detectada: {control_seq.hex()} ({control_sequence_length} bytes)")
        else:
            analysis_content.append(f"Nenhuma sequência de controle detectada")
    
    def _analyze_generic_specific(self, analysis_content: List[str], binary_data: bytes, offset: int, original_text: str):
        """Análise específica para arquivos genéricos."""
        analysis_content.append(f"ANÁLISE ESPECÍFICA GENÉRICA:")
        analysis_content.append(f"{'-'*32}")
        
        # Busca padrão 00 FF
        context_size = 100
        start = max(0, offset - context_size)
        end = min(len(binary_data), offset + context_size)
        context = binary_data[start:end]
        
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
            analysis_content.append(f"Padrões 00 FF encontrados em: {[hex(pos) for pos in ff_positions]}")
            for pos in ff_positions:
                if abs(pos - offset) < context_size:
                    distance = pos - offset
                    analysis_content.append(f"  {hex(pos)}: distância do offset = {distance} bytes")
        else:
            analysis_content.append(f"Nenhum padrão 00 FF encontrado no contexto")
    
    def remove_accents_simple(self, text: str) -> str:
        """Remove acentos usando mapeamento manual."""
        if not isinstance(text, str):
            return text

        result = text
        for accented, replacement in self.accent_map.items():
            result = result.replace(accented, replacement)
        
        return result
    
    # =================== ESTRATÉGIA STAGE ===================
    
    def detect_string_boundaries_stage(self, binary_data: bytes, offset: int, expected_text: str) -> Tuple[int, bytes]:
        """Detecção de boundaries para arquivos STAGE (sequências de controle múltiplas)."""
        try:
            clean_expected = expected_text
            
            for encoding in ['shift_jis', 'ascii', 'latin-1']:
                try:
                    expected_bytes = clean_expected.encode(encoding, errors='ignore')
                    
                    # Detecta sequências de controle de múltiplos bytes
                    control_sequence_length = 0
                    scan_pos = 0
                    max_control_scan = min(5, len(binary_data) - offset)
                    
                    while (scan_pos < max_control_scan and 
                           offset + scan_pos < len(binary_data) and
                           binary_data[offset + scan_pos] < 32):
                        control_sequence_length += 1
                        scan_pos += 1
                    
                    if self.debug_mode:
                        control_seq = binary_data[offset:offset + control_sequence_length]
                        logger.debug(f"[STAGE] Sequência de controle: {control_seq.hex()} ({control_sequence_length} bytes)")
                    
                    estimated_size = control_sequence_length + len(expected_bytes) + 1
                    actual_size = min(estimated_size, len(binary_data) - offset)
                    original_chunk = binary_data[offset:offset + actual_size]
                    
                    text_start = control_sequence_length
                    if (len(original_chunk) >= text_start + len(expected_bytes) and 
                        original_chunk[text_start:text_start + len(expected_bytes)] == expected_bytes):
                        
                        if self.debug_mode:
                            logger.debug(f"[STAGE] Match encontrado: {actual_size} bytes")
                        
                        return actual_size, original_chunk
                        
                except UnicodeEncodeError:
                    continue
            
            # Fallback conservador
            estimated_size = len(expected_text.encode('ascii', errors='ignore')) + 3
            actual_size = min(estimated_size, len(binary_data) - offset)
            
            if self.debug_mode:
                logger.debug(f"[STAGE] Fallback: {actual_size} bytes")
            
            return actual_size, binary_data[offset:offset + actual_size]
            
        except Exception as e:
            logger.error(f"Erro na detecção STAGE: {e}")
            safe_size = min(50, len(binary_data) - offset)
            return safe_size, binary_data[offset:offset + safe_size]
    
    def create_replacement_chunk_stage(self, original_chunk: bytes, new_text: str,
                                     offset: int, binary_data: bytes, original_text: str) -> Tuple[bytes, bool]:
        """Criação de substituição para arquivos STAGE (preserva sequências de controle completas)."""
        try:
            target_size = len(original_chunk)
            
            if self.debug_mode:
                logger.debug(f"[STAGE] Criando substituição: {target_size} bytes")
            
            # Detecta sequência de controle completa
            control_sequence = b''
            control_end = 0
            
            while (control_end < len(original_chunk) and 
                   original_chunk[control_end] < 32):
                control_end += 1
            
            if control_end > 0:
                control_sequence = original_chunk[0:control_end]
            
            if self.debug_mode:
                logger.debug(f"[STAGE] Sequência de controle: {control_sequence.hex()}")
            
            # Codifica novo texto
            try:
                new_bytes = new_text.encode('shift_jis', errors='ignore')
            except:
                try:
                    new_bytes = new_text.encode('ascii', errors='ignore')
                except:
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE ENCODING STAGE",
                        "Falha total no encoding"
                    )
                    return original_chunk, False
            
            # Verifica espaço disponível
            available_space = target_size - len(control_sequence) - 1
            
            if len(new_bytes) > available_space:
                overflow_amount = len(new_bytes) - available_space
                self.analyze_problem_and_export(
                    binary_data, offset, original_text, new_text,
                    "OVERFLOW STAGE",
                    f"Texto requer {len(new_bytes)} bytes mas só há {available_space} disponíveis. "
                    f"Overflow: {overflow_amount} bytes."
                )
                
                self.stats['skipped_size'] += 1
                return original_chunk, False
            
            # Constrói chunk
            result = bytearray(target_size)
            
            # 1. Sequência de controle
            if control_sequence:
                result[0:len(control_sequence)] = control_sequence
            
            # 2. Novo texto
            text_start = len(control_sequence)
            text_end = text_start + len(new_bytes)
            result[text_start:text_end] = new_bytes
            
            # 3. Null terminator
            if text_end < target_size:
                result[text_end] = 0x00
            
            # Verificações finais
            if len(result) != target_size:
                self.analyze_problem_and_export(
                    binary_data, offset, original_text, new_text,
                    "ERRO DE TAMANHO STAGE",
                    f"Chunk construído tem {len(result)} bytes mas deveria ter {target_size} bytes"
                )
                return original_chunk, False
            
            if control_sequence and not result.startswith(control_sequence):
                self.analyze_problem_and_export(
                    binary_data, offset, original_text, new_text,
                    "PERDA DE SEQUÊNCIA DE CONTROLE STAGE",
                    f"Sequência de controle perdida"
                )
                return original_chunk, False
            
            if self.debug_mode:
                logger.debug(f"[STAGE] Sucesso: chunk criado")
            
            return bytes(result), True
            
        except Exception as e:
            self.analyze_problem_and_export(
                binary_data, offset, original_text, new_text,
                "EXCEÇÃO STAGE",
                f"Exceção: {str(e)}"
            )
            return original_chunk, False
    
    # =================== ESTRATÉGIA GENÉRICA ===================
    
    def detect_string_exact_generic(self, binary_data: bytes, offset: int, expected_text: str) -> Tuple[int, bytes]:
        """Detecção exata para arquivos genéricos."""
        try:
            clean_expected = expected_text
            
            for encoding in ['shift_jis', 'ascii', 'latin-1']:
                try:
                    expected_bytes = clean_expected.encode(encoding, errors='ignore')
                    
                    max_scan = min(len(expected_bytes) + 50, len(binary_data) - offset)
                    scan_chunk = binary_data[offset:offset + max_scan]
                    
                    if scan_chunk.startswith(expected_bytes):
                        end_pos = offset + len(expected_bytes)
                        
                        # Conta terminadores
                        while end_pos < len(binary_data):
                            byte_val = binary_data[end_pos]
                            if byte_val in [0x00, 0xFF]:
                                end_pos += 1
                            else:
                                break
                        
                        total_size = end_pos - offset
                        original_chunk = binary_data[offset:end_pos]
                        
                        if self.debug_mode:
                            logger.debug(f"[GENERIC] String detectada: {total_size} bytes")
                        
                        return total_size, original_chunk
                        
                except UnicodeEncodeError:
                    continue
            
            # Fallback
            probe_size = min(len(expected_text) * 2 + 20, len(binary_data) - offset)
            probe_chunk = binary_data[offset:offset + probe_size]
            
            term_pos = offset
            for i, byte_val in enumerate(probe_chunk):
                if i > len(expected_text):
                    if byte_val in [0x00, 0xFF]:
                        continue
                    else:
                        term_pos = offset + i
                        break
            
            fallback_size = term_pos - offset
            fallback_chunk = binary_data[offset:offset + fallback_size]
            
            if self.debug_mode:
                logger.debug(f"[GENERIC] Fallback: {fallback_size} bytes")
            
            return fallback_size, fallback_chunk
            
        except Exception as e:
            logger.error(f"Erro na detecção genérica: {e}")
            safe_size = min(64, len(binary_data) - offset)
            return safe_size, binary_data[offset:offset + safe_size]
    
    def analyze_critical_pattern_generic(self, original_chunk: bytes) -> Dict:
        """Análise do padrão crítico 00 FF para arquivos genéricos."""
        analysis = {
            'has_00_ff': False,
            'ff_position': -1,
            'text_space': len(original_chunk),
            'control_bytes': b'',
            'terminator_sequence': b'',
            'full_terminator': b''
        }
        
        null_ff_pattern = b'\x00\xff'
        ff_pos = original_chunk.find(null_ff_pattern)
        
        if ff_pos != -1:
            analysis['has_00_ff'] = True
            analysis['ff_position'] = ff_pos
            analysis['text_space'] = ff_pos
            analysis['terminator_sequence'] = original_chunk[ff_pos:]
            analysis['full_terminator'] = original_chunk[ff_pos:]
            
            if self.debug_mode:
                logger.debug(f"[GENERIC] Padrão 00 FF detectado na posição {ff_pos}")
        
        return analysis
    
    def create_exact_replacement_generic(self, original_chunk: bytes, new_text: str,
                                       offset: int, binary_data: bytes, original_text: str) -> Tuple[bytes, bool]:
        """Criação de substituição para arquivos genéricos (foco no padrão 00 FF)."""
        try:
            clean_text = self.remove_accents_simple(new_text)
            
            # Preserva códigos de controle
            for control in self.codec_controls:
                if control in new_text:
                    clean_text = new_text
                    break
            
            # Análise crítica do padrão 00 FF
            critical_analysis = self.analyze_critical_pattern_generic(original_chunk)
            
            # Tenta codificar
            try:
                new_bytes = clean_text.encode('shift_jis', errors='ignore')
            except:
                try:
                    new_bytes = clean_text.encode('ascii', errors='ignore')
                except:
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE ENCODING GENERIC",
                        "Falha no encoding"
                    )
                    return original_chunk, False
            
            # Verifica padrão crítico
            if critical_analysis['has_00_ff']:
                # MODO CRÍTICO: Preserva 00 FF obrigatoriamente
                ff_position = critical_analysis['ff_position']
                
                control_prefix = b''
                text_start_pos = 0
                
                if len(original_chunk) > 0 and original_chunk[0] < 32:
                    control_prefix = original_chunk[0:1]
                    text_start_pos = 1
                
                available_space = ff_position - text_start_pos
                
                if len(new_bytes) > available_space:
                    self.stats['critical_pattern_lost'] += 1
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "OVERFLOW COM PADRÃO CRÍTICO GENERIC",
                        f"Texto requer {len(new_bytes)} bytes mas só há {available_space} disponíveis antes do 00 FF"
                    )
                    return original_chunk, False
                
                # Reconstrói preservando 00 FF
                result = bytearray()
                
                if control_prefix:
                    result.extend(control_prefix)
                
                result.extend(new_bytes)
                
                # Preenche até FF
                while len(result) < ff_position:
                    result.append(0x00)
                
                if len(result) > ff_position:
                    result = result[:ff_position]
                
                # Adiciona terminador preservado
                result.extend(critical_analysis['full_terminator'])
                
                # Verificações
                expected_size = len(original_chunk)
                actual_size = len(result)
                
                if actual_size != expected_size:
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE TAMANHO FINAL GENERIC",
                        f"Tamanho incorreto: {actual_size} != {expected_size}"
                    )
                    return original_chunk, False
                
                if b'\x00\xff' not in result:
                    self.stats['critical_pattern_lost'] += 1
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "PERDA DO PADRÃO CRÍTICO GENERIC",
                        "Padrão 00 FF foi perdido"
                    )
                    return original_chunk, False
                
                self.stats['critical_pattern_preserved'] += 1
                
                if self.debug_mode:
                    logger.debug(f"[GENERIC] Sucesso com preservação 00 FF")
                
                return bytes(result), True
                
            else:
                # MODO NORMAL: Sem padrão crítico
                available_space = len(original_chunk)
                
                control_prefix = b''
                if len(original_chunk) > 0 and original_chunk[0] < 32:
                    control_prefix = original_chunk[0:1]
                    available_space -= 1
                
                if len(new_bytes) > available_space:
                    self.stats['skipped_size'] += 1
                    
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "OVERFLOW SEM PADRÃO CRÍTICO GENERIC",
                        f"Texto muito grande: {len(new_bytes)} > {available_space}"
                    )
                    return original_chunk, False
                
                # Reconstrói normalmente
                result = bytearray()
                
                if control_prefix:
                    result.extend(control_prefix)
                
                result.extend(new_bytes)
                
                while len(result) < len(original_chunk):
                    result.append(0x00)
                
                if len(result) > len(original_chunk):
                    result = result[:len(original_chunk)]
                
                if self.debug_mode:
                    logger.debug(f"[GENERIC] Sucesso modo normal")
                
                return bytes(result), True
            
        except Exception as e:
            self.analyze_problem_and_export(
                binary_data, offset, original_text, new_text,
                "ERRO GERAL GENERIC",
                f"Exceção: {str(e)}"
            )
            return original_chunk, False

    def rebuild_binary_unified(self, binary_path: Path, csv_path: Path, output_path: Path, analysis_path: Path) -> bool:
        """Método unificado que aplica a estratégia correta baseada no tipo de arquivo."""
        try:
            # Determina estratégia
            self.current_strategy = self.determine_strategy(binary_path)
            self.stats['strategy_used'] = self.current_strategy
            
            # Configura arquivo de análise
            self.setup_analysis_file(analysis_path)

            # Carrega o arquivo binário original
            logger.info(f"Carregando arquivo binário: {binary_path.name}")
            with open(binary_path, "rb") as f:
                original_data = f.read()
            
            binary_data = bytearray(original_data)

            # Carrega as traduções
            logger.info(f"Carregando traduções: {csv_path.name}")
            
            df = None
            for delimiter in ['\t', ',', ';']:
                try:
                    df = pd.read_csv(csv_path, delimiter=delimiter)
                    if len(df.columns) > 1:
                        break
                except:
                    continue
            
            if df is None:
                logger.error("Não foi possível carregar o CSV")
                return False
            
            logger.info(f"Processando {len(df)} entradas com estratégia {self.current_strategy.upper()}...")
            
            # Ordena por offset
            df = df.sort_values('offset')
            
            # Processa cada entrada
            for index, row in df.iterrows():
                self.stats['processed'] += 1
                
                try:
                    # Extrai informações
                    offset = int(row["offset"], 16)
                    original_text = str(row["texto"]).strip()
                    
                    translated_text = str(row.get("texto_traduzido", "")).rstrip('\n\r ')
                    if not translated_text or translated_text.lower() in ['nan', 'none', '']:
                        text_to_use = original_text
                        is_modification = False
                    else:
                        text_to_use = translated_text
                        is_modification = True

                    # Se idêntico, pula
                    if text_to_use == original_text:
                        self.stats['identical_preserved'] += 1
                        if self.debug_mode:
                            logger.debug(f"Texto idêntico em {hex(offset)}")
                        continue

                    # Aplica estratégia específica
                    if self.current_strategy == "stage_strategy":
                        chunk_size, original_chunk = self.detect_string_boundaries_stage(
                            binary_data, offset, original_text
                        )
                        new_chunk, success = self.create_replacement_chunk_stage(
                            original_chunk, text_to_use, offset, binary_data, original_text
                        )
                    else:  # generic_strategy
                        chunk_size, original_chunk = self.detect_string_exact_generic(
                            binary_data, offset, original_text
                        )
                        new_chunk, success = self.create_exact_replacement_generic(
                            original_chunk, text_to_use, offset, binary_data, original_text
                        )
                        
                    if not success:
                        if self.debug_mode:
                            logger.debug(f"Substituição rejeitada para {hex(offset)}")
                        continue

                    # Verifica tamanho
                    if len(new_chunk) != len(original_chunk):
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "TAMANHO FINAL INCORRETO",
                            f"Chunk: {len(new_chunk)} != Esperado: {len(original_chunk)}"
                        )
                        continue

                    # Aplica modificação
                    binary_data[offset:offset + len(new_chunk)] = new_chunk
                    
                    self.stats['applied'] += 1
                    if is_modification:
                        self.stats['modified_applied'] += 1
                    
                    if self.debug_mode:
                        logger.debug(f"[{self.current_strategy.upper()}] Aplicado em {hex(offset)}")
                        
                except Exception as e:
                    logger.error(f"Erro ao processar linha {index}: {e}")
                    continue
            
            # Verificação final
            if len(binary_data) != len(original_data):
                logger.error(f"ERRO: Tamanho mudou! {len(original_data)} -> {len(binary_data)}")
                return False
            
            # Salva arquivo
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(binary_data)
            
            # Fecha análise
            if self.analysis_file:
                self.analysis_file.close()
                self.analysis_file = None
            
            self._log_statistics(output_path, analysis_path)
            return True
            
        except Exception as e:
            logger.error(f"Erro crítico: {e}")
            
            if self.analysis_file:
                try:
                    self.analysis_file.write(f"\nERRO CRÍTICO: {str(e)}\n")
                    self.analysis_file.close()
                except:
                    pass
                self.analysis_file = None
            
            return False
    
    def _log_statistics(self, output_path: Path, analysis_path: Path):
        """Registra estatísticas da operação."""
        logger.info(f"{'='*50}")
        logger.info(f"RECONSTRUÇÃO UNIFICADA CONCLUÍDA")
        logger.info(f"{'='*50}")
        logger.info(f"Estratégia utilizada: {self.current_strategy.upper()}")
        logger.info(f"Arquivo salvo em: {output_path}")
        logger.info(f"Entradas processadas: {self.stats['processed']}")
        logger.info(f"Modificações aplicadas: {self.stats['applied']}")
        logger.info(f"  - Textos idênticos preservados: {self.stats['identical_preserved']}")
        logger.info(f"  - Traduções aplicadas: {self.stats['modified_applied']}")
        
        if self.current_strategy == "generic_strategy":
            logger.info(f"Padrões críticos 00 FF preservados: {self.stats['critical_pattern_preserved']}")
            logger.info(f"Padrões críticos perdidos (rejeitados): {self.stats['critical_pattern_lost']}")
        
        logger.info(f"Puladas por tamanho: {self.stats['skipped_size']}")
        logger.info(f"Puladas por encoding: {self.stats['skipped_encoding']}")
        logger.info(f"Problemas analisados: {self.stats['problems_analyzed']}")
        
        success_rate = (self.stats['applied'] / self.stats['processed'] * 100) if self.stats['processed'] > 0 else 0
        logger.info(f"Taxa de sucesso: {success_rate:.1f}%")

        if self.stats['problems_analyzed'] > 0:
            logger.info(f"Arquivo de análise: {analysis_path}")

def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Rebuilder unificado MGS com estratégias específicas por tipo de arquivo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Estratégias por arquivo:
  STAGE.DIR  -> Estratégia avançada (sequências de controle múltiplas)
  Outros     -> Estratégia genérica (padrão crítico 00 FF)

Exemplos de uso:
  %(prog)s --stage                              # STAGE.DIR (estratégia avançada)
  %(prog)s --demo --debug                       # DEMO.DAT (estratégia genérica)
  %(prog)s --cd CD2 --vox                       # VOX.DAT (estratégia genérica)
  %(prog)s --list                               # Lista arquivos e estratégias
        """
    )
    
    cd_group = parser.add_argument_group('Seleção de CD')
    cd_group.add_argument(
        "--cd", 
        choices=list(FILE_MAPPING.keys()),
        default="CD1",
        help="CD para processar (padrão: CD1)"
    )
    
    file_group = parser.add_argument_group('Seleção de arquivo')
    file_group.add_argument(
        "--list", 
        action="store_true",
        help="Lista arquivos disponíveis com suas estratégias"
    )
    
    all_file_types = set()
    file_descriptions = {}
    
    for cd, files in FILE_MAPPING.items():
        for key, filename in files.items():
            all_file_types.add(key)
            if key not in file_descriptions:
                strategy = FILE_STRATEGIES.get(filename, "generic")
                file_descriptions[key] = f"{filename} [{strategy.replace('_', ' ').upper()}]"
    
    for file_key in sorted(all_file_types):
        file_group.add_argument(
            f"--{file_key}", 
            action="store_true",
            help=f"Reconstrói {file_descriptions[file_key]}"
        )
    
    compat_group = parser.add_argument_group('Compatibilidade')
    compat_group.add_argument("--binary", type=Path, help="Arquivo binário específico")
    compat_group.add_argument("--csv", type=Path, help="CSV específico")
    compat_group.add_argument("--output", type=Path, help="Arquivo de saída específico")
    compat_group.add_argument("--analysis", type=Path, help="Arquivo de análise específico")
    
    config_group = parser.add_argument_group('Configurações')
    config_group.add_argument("--no-strict", action="store_true", help="Desativa modo estrito")
    config_group.add_argument("--debug", action="store_true", help="Modo debug detalhado")
    
    return parser

def main():
    """Função principal do script."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(10)
    
    file_resolver = FileResolver(args.cd)
    
    if args.list:
        print(f"\n Arquivos disponíveis em {args.cd}:")
        print("-" * 80)
        available = file_resolver.list_available_files()
        if available:
            for line in available:
                print(f"  {line}")
        else:
            print(f"   Diretório {args.cd} não encontrado")
        print(f"\nLegenda das estratégias:")
        print(f"  STAGE STRATEGY    - Sequências de controle múltiplas (STAGE.DIR)")
        print(f"  GENERIC STRATEGY  - Padrão crítico 00 FF (demais arquivos)")
        return
    
    # Determina arquivos
    if args.binary:
        binary_file = args.binary
        csv_file = args.csv
        output_file = args.output
        analysis_file = args.analysis
        logger.info("Usando argumentos de compatibilidade")
    else:
        selected_files = []
        available_files = file_resolver.get_available_files()
        
        for key in available_files.keys():
            if getattr(args, key, False):
                selected_files.append(key)
        
        if len(selected_files) == 0:
            logger.error("Nenhum arquivo selecionado!")
            logger.info("Use --list para ver arquivos disponíveis")
            return
        elif len(selected_files) > 1:
            logger.error(f"Múltiplos arquivos selecionados: {', '.join(selected_files)}")
            return
        
        file_key = selected_files[0]
        binary_file = file_resolver.get_original_path(file_key)
        csv_file = file_resolver.get_csv_path(file_key)
        output_file = file_resolver.get_output_path(file_key)
        analysis_file = file_resolver.get_analysis_path(file_key)
        
        if not binary_file:
            logger.error(f"Arquivo original não encontrado: {file_key}")
            return
        
        if not csv_file:
            logger.error(f"CSV não encontrado: {file_key}")
            return
        
        logger.info(f" Arquivo selecionado: {file_key}")
        logger.info(f"   Original: {binary_file.name}")
        logger.info(f"   CSV: {csv_file.name}")
        logger.info(f"   Saída: {output_file.name}")
    
    # Valida arquivos
    if not binary_file or not binary_file.exists():
        logger.error(f"Arquivo binário não encontrado: {binary_file}")
        return
    
    if not csv_file or not csv_file.exists():
        logger.error(f"CSV não encontrado: {csv_file}")
        return
    
    if not output_file:
        output_file = Path("output_patched.bin")
    
    if not analysis_file:
        analysis_file = Path("insertion_problems.txt")
    
    # Executa reconstrução
    rebuilder = MGSRebuilderUnified(
        debug_mode=args.debug,
        strict_mode=not args.no_strict
    )
    
    logger.info(f" Iniciando reconstrução unificada...")
    logger.info(f"   Modo debug: {'ATIVO' if args.debug else 'INATIVO'}")
    logger.info(f"   Modo estrito: {'ATIVO' if not args.no_strict else 'INATIVO'}")
    
    success = rebuilder.rebuild_binary_unified(binary_file, csv_file, output_file, analysis_file)
    
    if success:
        logger.info(" RECONSTRUÇÃO UNIFICADA CONCLUÍDA COM SUCESSO!")
        logger.info(" CARACTERÍSTICAS DA VERSÃO UNIFICADA:")
        logger.info("   • Detecção automática do tipo de arquivo")
        logger.info("   • Estratégia otimizada por arquivo:")
        logger.info("     - STAGE.DIR: Sequências de controle avançadas")
        logger.info("     - Demais: Preservação do padrão crítico 00 FF")
        logger.info("   • Compatibilidade mantida com todos os arquivos")
        logger.info("   • Análise detalhada de problemas")
        logger.info(f"   • Consulte: {analysis_file}")
    else:
        logger.error(" Falha na reconstrução!")
        sys.exit(1)

if __name__ == "__main__":
    main()

    """
    Exemplos de uso:
    
    # Reconstrói STAGE.DIR do CD1
    python tools/rebuild_text.py --stage
    
    # Reconstrói DEMO.DAT com debug ativo
    python tools/rebuild_text.py --demo --debug
    
    # Reconstrói VOX.DAT do CD2
    python tools/rebuild_text.py --cd CD2 --vox
    
    # Lista arquivos disponíveis
    python tools/rebuild_text.py --list
        
    # Compatibilidade com primeira versão
    python tools/rebuild_text.py --binary arquivo.dat --csv traducoes.csv --output saida.dat
    """