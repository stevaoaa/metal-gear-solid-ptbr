#!/usr/bin/env python3
"""
Script para reconstruir arquivos binários com textos traduzidos - MGS PSX.
Versão completamente refeita com preservação absoluta de bytes de controle.
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
    Rebuilder completo para MGS PSX com preservação absoluta de bytes de controle.
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
            
            for encoding in ['shift_jis', 'ascii', 'latin-1', 'utf-8']:
                try:
                    decoded = sample_data.decode(encoding, errors='ignore')
                    clean_decoded = ''.join(c if ord(c) >= 32 else f'\\x{ord(c):02x}' for c in decoded[:50])
                    if clean_decoded.strip():
                        analysis_content.append(f"{encoding:>10}: '{clean_decoded}'")
                except Exception as e:
                    analysis_content.append(f"{encoding:>10}: ERRO - {str(e)}")
            
            # Análise do padrão crítico 00 FF
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
                analysis_content.append(f"Padrões 00 FF encontrados em: {[hex(pos) for pos in ff_positions]}")
                for pos in ff_positions:
                    if abs(pos - offset) < context_size:
                        distance = pos - offset
                        analysis_content.append(f"  {hex(pos)}: distância do offset = {distance} bytes")
            else:
                analysis_content.append(f"Nenhum padrão 00 FF encontrado no contexto")
            
            # Análise de espaço disponível
            analysis_content.append(f"\nANÁLISE DE ESPAÇO DISPONÍVEL:")
            analysis_content.append(f"{'-'*32}")
            
            try:
                chunk_size, original_chunk = self.detect_string_boundaries(binary_data, offset, original_text)
                analysis_content.append(f"Chunk original detectado: {len(original_chunk)} bytes")
                analysis_content.append(f"Hex do chunk: {original_chunk.hex()}")
                
                # Calcula requisitos do texto traduzido
                try:
                    translated_bytes = translated_text.encode('shift_jis', errors='ignore')
                    analysis_content.append(f"Texto traduzido requer: {len(translated_bytes)} bytes")
                    analysis_content.append(f"Texto traduzido (hex): {translated_bytes.hex()}")
                    
                    # Calcula espaço disponível
                    control_prefix_size = 1 if len(original_chunk) > 0 and original_chunk[0] < 32 else 0
                    available_space = len(original_chunk) - control_prefix_size - 1  # -1 para null terminator
                    
                    analysis_content.append(f"Espaço disponível: {available_space} bytes")
                    analysis_content.append(f"Espaço necessário: {len(translated_bytes)} bytes")
                    
                    if len(translated_bytes) > available_space:
                        overflow = len(translated_bytes) - available_space
                        analysis_content.append(f"OVERFLOW: {overflow} bytes a mais que o disponível")
                    else:
                        analysis_content.append(f"CABE: {available_space - len(translated_bytes)} bytes de sobra")
                    
                except Exception as e:
                    analysis_content.append(f"Erro ao analisar texto traduzido: {e}")
                    
            except Exception as e:
                analysis_content.append(f"Erro na detecção do chunk: {e}")
            
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
                logger.info(f"PROBLEMA #{self.stats['problems_analyzed']:03d}: {problem_type}")
                logger.info(f"Offset: {hex(offset)}")
                logger.info(f"Original:  '{original_text[:40]}{'...' if len(original_text) > 40 else ''}'")
                logger.info(f"Traduzido: '{translated_text[:40]}{'...' if len(translated_text) > 40 else ''}'")
                logger.info(f"Detalhes: {details}")
                logger.info(f"{'='*60}\n")
            
        except Exception as e:
            logger.error(f"Erro durante análise e exportação: {e}")
    
    def detect_string_boundaries(self, binary_data: bytes, offset: int, expected_text: str) -> Tuple[int, bytes]:
        """
        VERSÃO CORRIGIDA - Detecta sequências de bytes de controle múltiplos.
        """
        try:
            # Codifica o texto esperado
            for encoding in ['shift_jis', 'ascii', 'latin-1']:
                try:
                    expected_bytes = expected_text.encode(encoding, errors='ignore')
                    
                    # CORREÇÃO CRÍTICA: Detecta sequências de controle de múltiplos bytes
                    control_sequence_length = 0
                    scan_pos = 0
                    
                    # Escaneia bytes de controle consecutivos (< 32)
                    max_control_scan = min(5, len(binary_data) - offset)  # Máximo 5 bytes de controle
                    while (scan_pos < max_control_scan and 
                        offset + scan_pos < len(binary_data) and
                        binary_data[offset + scan_pos] < 32):
                        control_sequence_length += 1
                        scan_pos += 1
                    
                    if self.debug_mode:
                        control_seq = binary_data[offset:offset + control_sequence_length]
                        logger.debug(f"Sequência de controle detectada em {hex(offset)}: {control_seq.hex()} ({control_sequence_length} bytes)")
                    
                    # Calcula tamanho estimado: sequência_controle + texto + null_terminator
                    estimated_size = control_sequence_length + len(expected_bytes) + 1
                    
                    # Limita ao máximo disponível
                    actual_size = min(estimated_size, len(binary_data) - offset)
                    original_chunk = binary_data[offset:offset + actual_size]
                    
                    # Verifica se encontra match após a sequência de controle
                    text_start = control_sequence_length
                    if (len(original_chunk) >= text_start + len(expected_bytes) and 
                        original_chunk[text_start:text_start + len(expected_bytes)] == expected_bytes):
                        
                        if self.debug_mode:
                            logger.debug(f"Match encontrado em {hex(offset)}: {actual_size} bytes (control: {control_sequence_length})")
                        
                        return actual_size, original_chunk
                        
                except UnicodeEncodeError:
                    continue
            
            # Fallback: usa estimativa conservadora
            estimated_size = len(expected_text.encode('ascii', errors='ignore')) + 3  # +3 para controles
            actual_size = min(estimated_size, len(binary_data) - offset)
            
            if self.debug_mode:
                logger.debug(f"Fallback em {hex(offset)}: {actual_size} bytes")
            
            return actual_size, binary_data[offset:offset + actual_size]
            
        except Exception as e:
            logger.error(f"Erro na detecção de boundaries: {e}")
            safe_size = min(50, len(binary_data) - offset)
            return safe_size, binary_data[offset:offset + safe_size]
    
    def create_replacement_chunk(self, original_chunk: bytes, new_text: str,
                           offset: int, binary_data: bytes, original_text: str) -> Tuple[bytes, bool]:
        """
        VERSÃO CORRIGIDA - Preserva sequências de controle completas.
        """
        try:
            target_size = len(original_chunk)
            
            if self.debug_mode:
                logger.debug(f"Criando substituição em {hex(offset)}: {target_size} bytes")
                logger.debug(f"Chunk original: {original_chunk.hex()}")
            
            # CORREÇÃO CRÍTICA: Detecta sequência de controle completa
            control_sequence = b''
            control_end = 0
            
            # Escaneia TODOS os bytes de controle consecutivos
            while (control_end < len(original_chunk) and 
                original_chunk[control_end] < 32):
                control_end += 1
            
            if control_end > 0:
                control_sequence = original_chunk[0:control_end]
            
            if self.debug_mode:
                logger.debug(f"Sequência de controle: {control_sequence.hex()} ({len(control_sequence)} bytes)")
            
            # Codifica novo texto
            try:
                new_bytes = new_text.encode('shift_jis', errors='ignore')
            except:
                try:
                    new_bytes = new_text.encode('ascii', errors='ignore')
                except:
                    self.analyze_problem_and_export(
                        binary_data, offset, original_text, new_text,
                        "ERRO DE ENCODING CRÍTICO",
                        "Falha total no encoding"
                    )
                    return original_chunk, False
            
            # Verifica se cabe no espaço disponível
            available_space = target_size - len(control_sequence) - 1  # -1 para null terminator
            
            if len(new_bytes) > available_space:
                overflow_amount = len(new_bytes) - available_space
                self.analyze_problem_and_export(
                    binary_data, offset, original_text, new_text,
                    "REJEIÇÃO POR OVERFLOW",
                    f"Texto requer {len(new_bytes)} bytes mas só há {available_space} disponíveis. "
                    f"Overflow: {overflow_amount} bytes. Sequência controle: {len(control_sequence)} bytes, "
                    f"Chunk total: {target_size} bytes."
                )
                
                if self.debug_mode:
                    logger.debug(f"  REJEIÇÃO: {len(new_bytes)} > {available_space} bytes")
                
                self.stats['skipped_size'] += 1
                return original_chunk, False
            
            # Constrói chunk com tamanho exato
            result = bytearray(target_size)
            
            # 1. APLICA SEQUÊNCIA DE CONTROLE COMPLETA
            if control_sequence:
                result[0:len(control_sequence)] = control_sequence
            
            # 2. Adiciona novo texto após a sequência de controle
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
                    "ERRO DE TAMANHO FINAL",
                    f"Chunk construído tem {len(result)} bytes mas deveria ter {target_size} bytes"
                )
                return original_chunk, False
            
            # VERIFICAÇÃO CRÍTICA: Sequência de controle preservada
            if control_sequence and not result.startswith(control_sequence):
                self.analyze_problem_and_export(
                    binary_data, offset, original_text, new_text,
                    "PERDA DE SEQUÊNCIA DE CONTROLE",
                    f"Sequência de controle perdida. Esperado: {control_sequence.hex()}, "
                    f"Atual: {result[:len(control_sequence)].hex()}"
                )
                return original_chunk, False
            
            if self.debug_mode:
                logger.debug(f"  SUCESSO: chunk criado com sequência {result[:len(control_sequence)].hex()}")
            
            return bytes(result), True
            
        except Exception as e:
            self.analyze_problem_and_export(
                binary_data, offset, original_text, new_text,
                "EXCEÇÃO DURANTE SUBSTITUIÇÃO",
                f"Exceção não capturada: {str(e)}"
            )
            logger.error(f"Erro na substituição: {e}")
            return original_chunk, False 
    
    def rebuild_binary(self, binary_path: Path, csv_path: Path, output_path: Path, analysis_path: Path) -> bool:
        """
        Reconstrói o arquivo binário com textos traduzidos.
        """
        try:
            # Configura arquivo de análise
            self.setup_analysis_file(analysis_path)

            # Carrega o arquivo binário original
            logger.info(f"Carregando arquivo binário: {binary_path.name}")
            with open(binary_path, "rb") as f:
                original_data = f.read()
            
            # Cria uma cópia para modificação
            binary_data = bytearray(original_data)

            # Carrega as traduções
            logger.info(f"Carregando traduções: {csv_path.name}")
            
            # Tenta diferentes delimitadores
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
            
            logger.info(f"Processando {len(df)} entradas...")
            
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
                    # Remove apenas quebras de linha e espaços no final, preservando espaços intencionais no início
                    translated_text = str(row.get("texto_traduzido", "")).rstrip('\n\r ')
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

                    # Detecta boundaries da string
                    try:
                        chunk_size, original_chunk = self.detect_string_boundaries(
                            binary_data, offset, original_text
                        )
                    except Exception as e:
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "FALHA NA DETECÇÃO DE STRING",
                            f"Erro durante detecção de boundaries: {str(e)}"
                        )
                        continue

                    # Cria substituição
                    try:
                        new_chunk, success = self.create_replacement_chunk(
                            original_chunk, text_to_use, offset, binary_data, original_text
                        )
                        
                        if not success:
                            if self.debug_mode:
                                logger.debug(f"Substituição rejeitada para {hex(offset)}")
                            continue

                    except Exception as e:
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "EXCEÇÃO NA CRIAÇÃO DE SUBSTITUIÇÃO",
                            f"Exceção não capturada: {str(e)}"
                        )
                        continue

                    # Verifica tamanho final
                    if len(new_chunk) != len(original_chunk):
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "TAMANHO FINAL INCORRETO",
                            f"Chunk criado: {len(new_chunk)} bytes, Esperado: {len(original_chunk)} bytes"
                        )
                        continue

                    # Aplica a modificação
                    try:
                        binary_data[offset:offset + len(new_chunk)] = new_chunk
                        
                        self.stats['applied'] += 1
                        if is_modification:
                            self.stats['modified_applied'] += 1
                        
                        if self.debug_mode:
                            logger.debug(f"Aplicado em {hex(offset)}: '{text_to_use[:30]}...'")

                    except Exception as e:
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, text_to_use,
                            "FALHA NA APLICAÇÃO FINAL",
                            f"Erro ao aplicar chunk: {str(e)}"
                        )
                        continue
                        
                except Exception as e:
                    # Análise de erro geral
                    try:
                        error_text = text_to_use if 'text_to_use' in locals() else "N/A"
                        self.analyze_problem_and_export(
                            binary_data, offset, original_text, error_text,
                            "ERRO GERAL DE PROCESSAMENTO",
                            f"Exceção durante processamento da linha {index}: {str(e)}"
                        )
                    except:
                        logger.error(f"Falha crítica ao processar {hex(offset)}: {e}")
                    
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
        logger.info(f"RECONSTRUÇÃO CONCLUÍDA")
        logger.info(f"{'='*50}")
        logger.info(f"Arquivo salvo em: {output_path}")
        logger.info(f"Entradas processadas: {self.stats['processed']}")
        logger.info(f"Modificações aplicadas: {self.stats['applied']}")
        logger.info(f"  - Textos idênticos preservados: {self.stats['identical_preserved']}")
        logger.info(f"  - Traduções efetivamente aplicadas: {self.stats['modified_applied']}")
        logger.info(f"Correções de encoding: {self.stats['encoding_fixes']}")
        logger.info(f"Puladas por tamanho: {self.stats['skipped_size']}")
        logger.info(f"Puladas por encoding: {self.stats['skipped_encoding']}")
        logger.info(f"Problemas analisados e exportados: {self.stats['problems_analyzed']}")
        
        success_rate = (self.stats['applied'] / self.stats['processed'] * 100) if self.stats['processed'] > 0 else 0
        logger.info(f"Taxa de sucesso: {success_rate:.1f}%")

        general_success = ((self.stats['applied'] + self.stats['identical_preserved']) / self.stats['processed'] * 100) if self.stats['processed'] > 0 else 0
        logger.info(f"Taxa de sucesso geral (traduzidos + preservados): {general_success:.1f}%")
        
        if self.stats['problems_analyzed'] > 0:
            logger.info(f"ARQUIVO DE ANÁLISE DE PROBLEMAS:")
            logger.info(f"  Local: {analysis_path}")
            logger.info(f"  Problemas documentados: {self.stats['problems_analyzed']}")
            logger.info(f"  Use este arquivo para investigar problemas detalhadamente")

def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Reconstrói arquivos binários MGS com preservação de bytes de controle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --stage                              # Reconstrói STAGE.DIR do CD1
  %(prog)s --demo --debug                       # Reconstrói DEMO.DAT com debug
  %(prog)s --cd CD2 --vox                       # Reconstrói VOX.DAT do CD2
  %(prog)s --list                               # Lista arquivos disponíveis
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
    
    # Coleta todos os tipos de arquivo únicos
    all_file_types = set()
    file_descriptions = {}
    
    for cd, files in FILE_MAPPING.items():
        for key, filename in files.items():
            all_file_types.add(key)
            if key not in file_descriptions:
                file_descriptions[key] = filename
    
    # Adiciona argumentos para cada tipo de arquivo
    for file_key in sorted(all_file_types):
        file_group.add_argument(
            f"--{file_key}", 
            action="store_true",
            help=f"Reconstrói {file_descriptions[file_key]}"
        )
    
    # Argumentos de compatibilidade
    compat_group = parser.add_argument_group('Compatibilidade')
    compat_group.add_argument(
        "--binary", 
        type=Path,
        help="Caminho específico do arquivo binário original"
    )
    compat_group.add_argument(
        "--csv", 
        type=Path,
        help="Caminho específico do CSV com traduções"
    )
    compat_group.add_argument(
        "--output", 
        type=Path,
        help="Caminho específico do arquivo de saída"
    )
    compat_group.add_argument(
        "--analysis", 
        type=Path,
        help="Caminho específico do arquivo de análise"
    )
    
    # Configurações
    config_group = parser.add_argument_group('Configurações')
    config_group.add_argument(
        "--no-strict", 
        action="store_true",
        help="Desativa modo estrito"
    )
    config_group.add_argument(
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
    if args.binary:
        # Modo compatibilidade
        binary_file = args.binary
        csv_file = args.csv
        output_file = args.output
        analysis_file = args.analysis
        logger.info("Usando argumentos de compatibilidade")
    else:
        # Modo novo
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
            logger.info("Selecione apenas um arquivo por vez")
            return
        
        # Resolve arquivo selecionado
        file_key = selected_files[0]
        binary_file = file_resolver.get_original_path(file_key)
        csv_file = file_resolver.get_csv_path(file_key)
        output_file = file_resolver.get_output_path(file_key)
        analysis_file = file_resolver.get_analysis_path(file_key)
        
        if not binary_file:
            logger.error(f"Arquivo original não encontrado: {file_key}")
            return
        
        if not csv_file:
            logger.error(f"CSV com traduções não encontrado: {file_key}")
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
    
    logger.info(f" Iniciando reconstrução...")
    logger.info(f"   Modo debug: {'ATIVO' if args.debug else 'INATIVO'}")
    logger.info(f"   Modo estrito: {'ATIVO' if not args.no_strict else 'INATIVO'}")
    
    success = rebuilder.rebuild_binary(binary_file, csv_file, output_file, analysis_file)
    
    if success:
        logger.info(" RECONSTRUÇÃO CONCLUÍDA COM SUCESSO!")
        logger.info(" DICAS IMPORTANTES:")
        logger.info("   • Teste no emulador com save state")
        logger.info("   • Bytes de controle foram preservados")
        logger.info("   • Estrutura binária mantida intacta")
        logger.info(f"   • Consulte o arquivo de análise: {analysis_file}")
    else:
        logger.error(" Falha na reconstrução!")
        sys.exit(1)

if __name__ == "__main__":
    main()