#!/usr/bin/env python3
"""
Script para reconstruir arquivos binários com textos traduzidos - MGS PSX.
VERSÃO CORRIGIDA: Preserva OBRIGATORIAMENTE o padrão crítico 00 FF.
"""

import os
import sys
import unicodedata
import pandas as pd
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import struct

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
    'output': BASE_DIR / "patches" / "RADIO_PATCHED.DAT"
}

class MGSFixedRebuilder:
    """
    Versão CORRIGIDA para reconstrução de textos do MGS PSX.
    GARANTIA ABSOLUTA de preservação do padrão crítico 00 FF.
    """
    
    def __init__(self, debug_mode: bool = False, strict_mode: bool = True):
        self.debug_mode = debug_mode
        self.strict_mode = strict_mode
        self.stats = {
            'processed': 0,
            'applied': 0,
            'skipped_encoding': 0,
            'skipped_size': 0,
            'identical_preserved': 0,
            'modified_applied': 0,
            'encoding_fixes': 0,
            'critical_pattern_preserved': 0,
            'critical_pattern_lost': 0
        }
        
        # Tabela de substituição para acentos (específica para Shift-JIS)
        self.accent_map = {
            # Vogais acentuadas
            'á': 'a', 'à': 'a', 'ã': 'a', 'â': 'a', 'ä': 'a',
            'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
            'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
            'ó': 'o', 'ò': 'o', 'õ': 'o', 'ô': 'o', 'ö': 'o',
            'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
            'Á': 'A', 'À': 'A', 'Ã': 'A', 'Â': 'A', 'Ä': 'A',
            'É': 'E', 'È': 'E', 'Ê': 'E', 'Ë': 'E',
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
    
    def create_exact_replacement_with_critical_preservation(self, original_chunk: bytes, new_text: str) -> Tuple[bytes, bool]:
        """
        Cria substituição GARANTINDO preservação do padrão crítico 00 FF.
        Se não conseguir preservar, REJEITA a substituição.
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
                    return original_chunk, False
                
                # VERIFICAÇÃO FINAL: Confirma que 00 FF está presente
                if b'\x00\xff' not in result:
                    logger.error(f"FALHA CRÍTICA: Padrão 00 FF foi perdido durante a reconstrução!")
                    self.stats['critical_pattern_lost'] += 1
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
            return original_chunk, False
    
    def debug_specific_offset(self, binary_data: bytes, offset: int, context_size: int = 100):
        """
        Debug específico para um offset problemático.
        """
        logger.info(f" ANÁLISE DETALHADA DO OFFSET {hex(offset)}:")
        
        start = max(0, offset - context_size)
        end = min(len(binary_data), offset + context_size)
        context = binary_data[start:end]
        
        logger.info(f"Contexto ({hex(start)} - {hex(end)}):")
        
        # Mostra em hex
        for i in range(0, min(len(context), 64), 16):
            chunk = context[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            addr = start + i
            logger.info(f"{addr:08x}: {hex_part:<48} |{ascii_part}|")
        
        # Tenta decodificar o texto no offset específico
        for encoding in ['shift_jis', 'ascii', 'latin-1']:
            try:
                decoded = context[offset-start:offset-start+50].decode(encoding, errors='ignore')
                if decoded.strip():
                    logger.info(f"Texto decodificado ({encoding}): '{decoded[:50]}'")
            except:
                continue

    def rebuild_binary_fixed(self, binary_path: Path, csv_path: Path, output_path: Path) -> bool:
        """
        Reconstrói o binário com GARANTIA de preservação do padrão crítico 00 FF.
        """
        try:
            # Carrega o arquivo binário original
            logger.info(f"Carregando arquivo binário: {binary_path}")
            with open(binary_path, "rb") as f:
                original_data = f.read()
            
            # Cria uma cópia para modificação
            binary_data = bytearray(original_data)
            
            # Carrega as traduções
            logger.info(f"Carregando traduções: {csv_path}")
            df = pd.read_csv(csv_path)
            
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
                    
                    # Debug específico para o offset problemático
                    if offset == 0x47b96:
                        logger.info(f"  PROCESSANDO OFFSET PROBLEMÁTICO: {hex(offset)}")
                        self.debug_specific_offset(binary_data, offset)
                    
                    # Detecta boundaries exatas da string
                    chunk_size, original_chunk = self.detect_string_exact(
                        binary_data, offset, original_text
                    )
                    
                    # Debug adicional para o offset problemático
                    if offset == 0x47b96:
                        logger.info(f"Chunk detectado para {hex(offset)}:")
                        logger.info(f"  Tamanho: {len(original_chunk)} bytes")
                        logger.info(f"  Hex: {original_chunk.hex()}")
                        logger.info(f"  Texto original: '{original_text}'")
                        logger.info(f"  Texto traduzido: '{text_to_use}'")
                        
                        # Análise específica do padrão 00 FF
                        ff_pattern = b'\x00\xff'
                        if ff_pattern in original_chunk:
                            ff_pos = original_chunk.find(ff_pattern)
                            logger.info(f"   Padrão crítico 00 FF encontrado na posição {ff_pos}")
                        else:
                            logger.warning(f"    Padrão crítico 00 FF NÃO encontrado!")
                    
                    # CRIA SUBSTITUIÇÃO COM PRESERVAÇÃO CRÍTICA GARANTIDA
                    new_chunk, success = self.create_exact_replacement_with_critical_preservation(
                        original_chunk, text_to_use
                    )
                    
                    if not success:
                        logger.warning(f"Substituição REJEITADA para offset {hex(offset)} (padrão crítico não preservado)")
                        continue
                    
                    # Debug final para o offset problemático
                    if offset == 0x47b96:
                        logger.info(f"Substituição criada para {hex(offset)}:")
                        logger.info(f"  Novo hex: {new_chunk.hex()}")
                        logger.info(f"  Comparação:")
                        logger.info(f"    Original: {original_chunk.hex()}")
                        logger.info(f"    Novo:     {new_chunk.hex()}")
                        
                        # Verifica preservação do padrão crítico
                        if b'\x00\xff' in original_chunk:
                            if b'\x00\xff' in new_chunk:
                                logger.info(f"  SUCESSO: Padrão crítico 00 FF preservado!")
                            else:
                                logger.error(f"  ERRO IMPOSSÍVEL: Padrão crítico perdido após verificação!")
                                continue
                    
                    # Aplica a mudança - PRESERVANDO TAMANHO EXATO
                    if len(new_chunk) != len(original_chunk):
                        logger.error(f"ERRO CRÍTICO: Tamanhos não coincidem em {hex(offset)}")
                        continue
                    
                    binary_data[offset:offset + len(new_chunk)] = new_chunk
                    
                    self.stats['applied'] += 1
                    if is_modification:
                        self.stats['modified_applied'] += 1
                    
                    if self.debug_mode:
                        logger.debug(f"Aplicado em {hex(offset)}: '{text_to_use[:30]}...'")
                        
                except Exception as e:
                    logger.error(f"Erro ao processar linha {index} (offset {hex(offset)}): {e}")
                    continue
            
            # Verificação final: tamanho do arquivo
            if len(binary_data) != len(original_data):
                logger.error(f"ERRO CRÍTICO: Tamanho do arquivo mudou! {len(original_data)} -> {len(binary_data)}")
                return False
            
            # Salva o arquivo de saída
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(binary_data)
            
            self._log_statistics(output_path)
            return True
            
        except Exception as e:
            logger.error(f"Erro crítico durante a reconstrução: {e}")
            return False
    
    def _log_statistics(self, output_path: Path):
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
        
        success_rate = (self.stats['applied'] / self.stats['processed'] * 100) if self.stats['processed'] > 0 else 0
        logger.info(f"Taxa de sucesso: {success_rate:.1f}%")
        
        if self.stats['critical_pattern_preserved'] > 0:
            logger.info(f"PADRÕES CRÍTICOS 00 FF PRESERVADOS COM SUCESSO!")
        
        if self.stats['critical_pattern_lost'] > 0:
            logger.warning(f"  {self.stats['critical_pattern_lost']} substituições foram rejeitadas para preservar padrões críticos")


def main():
    """Função principal do script."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Reconstrói arquivos binários MGS com preservação garantida do padrão crítico 00 FF")
    parser.add_argument("--binary", type=Path, default=DEFAULT_PATHS['original'],
                       help="Arquivo binário original")
    parser.add_argument("--csv", type=Path, default=DEFAULT_PATHS['csv'], 
                       help="Arquivo CSV com traduções")
    parser.add_argument("--output", type=Path, default=DEFAULT_PATHS['output'],
                       help="Arquivo de saída")
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
    rebuilder = MGSFixedRebuilder(
        debug_mode=args.debug,
        strict_mode=not args.no_strict
    )
    
    success = rebuilder.rebuild_binary_fixed(args.binary, args.csv, args.output)
    
    if success:
        logger.info("RECONSTRUÇÃO CONCLUÍDA COM SUCESSO!")
        logger.info("DICAS IMPORTANTES:")
        logger.info("   • Teste no emulador com save state")
        logger.info("   • Padrões críticos 00 FF foram preservados obrigatoriamente")
        logger.info("   • Substituições que danificariam o padrão foram rejeitadas")
        logger.info("   • Acentos foram removidos automaticamente para compatibilidade")
        logger.info("   • Endereços foram preservados exatamente")
    else:
        logger.error("Falha na reconstrução!")
        sys.exit(1)


if __name__ == "__main__":
    main()