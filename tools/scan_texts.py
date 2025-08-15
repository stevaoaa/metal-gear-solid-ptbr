#!/usr/bin/env python3
"""
Script para extração de textos de arquivos binários do Metal Gear Solid PSX.
Suporta múltiplos encodings e oferece configuração flexível.
"""

import os
import sys
import csv
import argparse
import json
from pathlib import Path
from typing import List, Tuple, Optional, Set, Dict
from dataclasses import dataclass

# Caminho absoluto da raiz do projeto
BASE_DIR = Path(__file__).parent.parent.absolute()

# Adiciona o diretório raiz ao sys.path para permitir imports relativos
sys.path.append(str(BASE_DIR))
from util.logger_config import setup_logger

# Inicializa o logger
logger = setup_logger()

# Mapeamento de arquivos disponíveis por CD
FILE_MAPPING = {
    "CD1": {
        # Arquivos do CD1
        "radio": "RADIO.DAT",
        "brf": "BRF.DAT", 
        "stage": "STAGE.DIR",
        "face": "FACE.DAT",
        "demo": "DEMO.DAT",
        "vox": "VOX.DAT",
        "slus": "SLUS_005.94",
        "zmovie": "ZMOVIE.STR"
    },
    "CD2": {
        # Arquivos do CD2
        "radio": "RADIO.DAT",
        "brf": "BRF.DAT",
        "stage": "STAGE.DIR",
        "face": "FACE.DAT",
        "demo": "DEMO.DAT",
        "vox": "VOX.DAT"
    }
}

# Arquivos padrão para processamento (mais comuns para texto)
DEFAULT_FILES = ["radio", "brf", "stage", "face", "demo", "vox"]


@dataclass
class TextExtractorConfig:
    """Configuração para o extrator de textos."""
    min_length: int = 4
    max_length: int = 1000
    encodings: List[str] = None
    output_dir: str = "extracted"
    skip_validation: bool = False
    control_codes: List[str] = None  # Códigos de controle a serem tratados como delimitadores
    
    def __post_init__(self):
        if self.encodings is None:
            self.encodings = ["shift_jis", "utf-8", "latin-1"]
        if self.control_codes is None:
            self.control_codes = ["#N", "#P", "#W", "#C"]  # Códigos comuns do MGS


class TextExtractor:
    """Classe responsável pela extração de textos de arquivos binários."""
    
    def __init__(self, config: TextExtractorConfig, merge_translations: bool = True):
        self.config = config
        self.merge_translations = merge_translations
        self.output_dir = BASE_DIR / config.output_dir
        self.output_dir.mkdir(exist_ok=True)
    
    def extract_texts(self, file_path: Path) -> List[Tuple[int, str, int, str]]:
        """
        Extrai textos de um arquivo binário usando abordagem byte-a-byte.
        Reconhece tanto null bytes quanto códigos de controle como delimitadores.
        
        Args:
            file_path: Caminho para o arquivo binário
            
        Returns:
            Lista de tuplas (offset, texto, tamanho_em_bytes, encoding)
        """
        logger.info(f"Iniciando extração de: {file_path.name}")
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except IOError as e:
            logger.error(f"Erro ao ler arquivo {file_path}: {e}")
            return []
        
        results = []
        found_texts: Set[str] = set()
        data_size = len(data)
        i = 0
        
        logger.debug(f"Arquivo carregado: {data_size} bytes")
        
        while i < data_size:
            # Pula bytes nulos (delimitadores ou padding)
            if data[i] == 0x00:
                i += 1
                continue

            # Encontra o final do segmento atual
            # Considera tanto null bytes quanto códigos de controle configurados
            j = i
            while j < data_size:
                if data[j] == 0x00:
                    break
                
                # Verifica códigos de controle configurados
                for control_code in self.config.control_codes:
                    if j <= data_size - len(control_code):
                        # Converte o código para bytes e compara
                        code_bytes = control_code.encode('ascii')
                        if data[j:j+len(code_bytes)] == code_bytes:
                            # Inclui o código de controle no chunk atual
                            j += len(code_bytes)
                            logger.debug(f"Delimitador encontrado: {control_code} no offset {hex(j-len(code_bytes))}")
                            break
                else:
                    # Se não encontrou nenhum código de controle, continua
                    j += 1
                    continue
                # Se encontrou um código de controle, sai do while
                break

            # Processa o chunk encontrado
            chunk = data[i:j]
            if len(chunk) >= self.config.min_length:
                text_result = self._try_decode_chunk(chunk, i)
                
                if text_result and text_result[1] not in found_texts:
                    results.append(text_result)
                    found_texts.add(text_result[1])
                    logger.debug(f"Texto encontrado no offset {hex(i)}: {text_result[1][:50]}...")
            
            # Move para o próximo segmento
            i = j if j > i else i + 1
        
        logger.info(f"Extraídos {len(results)} textos únicos de {file_path.name}")
        return results
    
    def _try_decode_chunk(self, chunk: bytes, offset: int) -> Optional[Tuple[int, str, int, str]]:
        """
        Tenta decodificar um chunk de bytes com diferentes encodings.
        Versão mais agressiva para capturar mais textos.
        
        Args:
            chunk: Bytes para decodificar
            offset: Posição no arquivo original
            
        Returns:
            Tupla (offset, texto, tamanho, encoding) ou None se não conseguir decodificar
        """
        if len(chunk) < self.config.min_length or len(chunk) > self.config.max_length:
            return None
        
        for encoding in self.config.encodings:
            try:
                # Decodifica o texto
                text = chunk.decode(encoding)
                
                # ADICIONADO: Remove caracteres problemáticos ANTES da validação
                cleaned_text = self._clean_extracted_text(text)
                
                # Log para debug
                logger.debug(f"Tentando decodificar chunk no offset {hex(offset)} com {encoding}: '{cleaned_text[:30]}...'")
                
                # Valida se é um texto útil (ou pula validação se configurado)
                if self.config.skip_validation or self._is_valid_text(cleaned_text):
                    logger.debug(f"✓ Texto {'aceito sem validação' if self.config.skip_validation else 'válido'} encontrado com {encoding}: '{cleaned_text[:50]}...'")
                    # Retorna o texto LIMPO
                    return (offset, cleaned_text, len(chunk), encoding)
                else:
                    logger.debug(f"✗ Texto rejeitado pela validação: '{cleaned_text[:30]}...'")
                    
            except (UnicodeDecodeError, UnicodeError) as e:
                logger.debug(f"✗ Falha ao decodificar com {encoding} no offset {hex(offset)}: {str(e)[:50]}")
                continue
        
        return None

    def _clean_extracted_text(self, text: str) -> str:
        """
        Remove caracteres problemáticos do texto extraído.
        
        Args:
            text: Texto bruto extraído
            
        Returns:
            Texto limpo, seguro para recodificação
        """
        # Remove caracteres \xff que causam problemas no shift_jis
        cleaned = text.replace('\xff', '')
        
        # Remove outros caracteres de controle problemáticos, mas preserva quebras de linha
        cleaned = ''.join(char for char in cleaned 
                        if char.isprintable() or char in '\n\r\t' or ord(char) in [0x20])  # espaço
        
        # Remove espaços em excesso e null bytes do final
        cleaned = cleaned.rstrip('\x00').strip()
        
        return cleaned

    
    def _is_valid_text(self, text: str) -> bool:
        """
        Verifica se o texto extraído é válido.
        Versão simples focada em ASCII para filtrar dados binários.
        """
        if len(text) < self.config.min_length:
            return False
        
        stripped_text = text.strip()
        if not stripped_text:
            return False
        
        # 1. FILTRO PRINCIPAL: Porcentagem de ASCII imprimível (32-126)
        ascii_printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        ascii_ratio = ascii_printable / len(text)
        
        if ascii_ratio < 0.90:  # Pelo menos 90% ASCII
            logger.debug(f"Rejeitado: {ascii_ratio:.1%} ASCII: '{stripped_text[:30]}...'")
            return False
        
        # 2. FILTRO ANTI-LIXO: Caracteres comuns em dados binários
        binary_junk = 'ÁßÀáàâäãåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂ©®±²³µ¶·¸¹½¼¾'
        if any(c in text for c in binary_junk):
            logger.debug(f"Rejeitado: caracteres binários: '{stripped_text[:30]}...'")
            return False
        
        # 3. Deve ter letras suficientes (não só números/símbolos)
        letters = sum(1 for c in text if c.isalpha())
        if letters < max(3, len(text) * 0.3):  # Mínimo 3 letras OU 30%
            logger.debug(f"Rejeitado: poucas letras: '{stripped_text[:30]}...'")
            return False
        
        logger.debug(f"✓ Aceito: '{stripped_text[:50]}...'")
        return True
    
    def save_results(self, file_path: Path, results: List[Tuple[int, str, int, str]]) -> Path:
        """
        Salva os resultados em um arquivo CSV com coluna de tradução.
        Se já existir um arquivo traduzido, mescla as traduções existentes.
        
        Args:
            file_path: Caminho do arquivo original
            results: Lista de resultados da extração
            
        Returns:
            Caminho do arquivo CSV criado
        """
        base_name = file_path.stem
        output_file = self.output_dir / f"strings_{base_name}.csv"
        
        # Verifica se existe arquivo traduzido para mesclar
        translated_dir = BASE_DIR / "translated"
        existing_translated = translated_dir / f"strings_{base_name}_traduzido.csv"
        
        existing_translations = {}
        if self.merge_translations and existing_translated.exists():
            logger.info(f"Mesclando com traduções existentes: {existing_translated}")
            try:
                import pandas as pd
                df_existing = pd.read_csv(existing_translated)
                for _, row in df_existing.iterrows():
                    offset = row.get('offset', '')
                    translation = row.get('texto_traduzido', '')
                    if offset and translation and str(translation).strip():
                        existing_translations[offset] = str(translation).strip()
                logger.info(f"Carregadas {len(existing_translations)} traduções existentes")
            except Exception as e:
                logger.warning(f"Erro ao carregar traduções existentes: {e}")
        elif not self.merge_translations:
            logger.info("Mesclagem de traduções desabilitada")
        
        try:
            with open(output_file, "w", newline='', encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                # Cabeçalho com coluna de tradução
                writer.writerow(["offset", "texto", "tamanho_bytes", "encoding", "texto_traduzido"])
                
                for offset, text, size, encoding in results:
                    offset_hex = hex(offset)
                    # Usa tradução existente se disponível, senão deixa vazio
                    existing_translation = existing_translations.get(offset_hex, "")
                    writer.writerow([offset_hex, text, size, encoding, existing_translation])
            
            logger.info(f"{len(results)} textos salvos em: {output_file}")
            if existing_translations:
                preserved_count = sum(1 for offset, _, _, _ in results 
                                    if existing_translations.get(hex(offset), ""))
                logger.info(f"Traduções preservadas: {preserved_count}")
            
            return output_file
            
        except IOError as e:
            logger.error(f"Erro ao salvar arquivo {output_file}: {e}")
            raise


class FileManager:
    """Gerencia a lista de arquivos para processamento."""
    
    def __init__(self, cd: str = "CD1"):
        self.cd = cd
        self.config_file = BASE_DIR / "tools" / "scan_config.json"
        self.base_path = BASE_DIR / "assets" / "fontes" / cd
    
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
    
    def list_available_files(self) -> List[str]:
        """Lista todos os arquivos disponíveis no diretório do CD."""
        if not self.base_path.exists():
            return []
        
        available_files = []
        file_mapping = self.get_available_files()
        
        for key, filename in file_mapping.items():
            file_path = self.base_path / filename
            status = "✓" if file_path.exists() else "✗"
            size = ""
            if file_path.exists():
                size_bytes = file_path.stat().st_size
                if size_bytes > 1024*1024:
                    size = f"({size_bytes // (1024*1024)} MB)"
                else:
                    size = f"({size_bytes // 1024} KB)"
            
            available_files.append(f"{status} --{key:<8} {filename:<15} {size}")
        
        return available_files
    
    def get_default_files(self) -> List[Path]:
        """Retorna a lista padrão de arquivos para processamento."""
        files = []
        for file_key in DEFAULT_FILES:
            file_path = self.get_file_path(file_key)
            if file_path:
                files.append(file_path)
        return files
    
    def resolve_files(self, file_keys: List[str]) -> List[Path]:
        """Resolve uma lista de chaves de arquivos para caminhos completos."""
        resolved_files = []
        
        for key in file_keys:
            file_path = self.get_file_path(key)
            if file_path:
                resolved_files.append(file_path)
                logger.info(f"Arquivo selecionado: {key} -> {file_path.name}")
            else:
                logger.warning(f"Arquivo não encontrado: {key} ({self.cd})")
        
        return resolved_files
    
    def load_files_from_config(self) -> List[Path]:
        """Carrega lista de arquivos do arquivo de configuração."""
        if not self.config_file.exists():
            return self.get_default_files()
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                files = config.get('files', [])
                return [Path(f) for f in files if Path(f).exists()]
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Erro ao carregar configuração: {e}. Usando arquivos padrão.")
            return self.get_default_files()
    
    def save_config(self, files: List[Path], config: TextExtractorConfig):
        """Salva a configuração atual."""
        config_data = {
            'cd': self.cd,
            'files': [str(f) for f in files],
            'extractor_config': {
                'min_length': config.min_length,
                'max_length': config.max_length,
                'encodings': config.encodings,
                'output_dir': config.output_dir
            }
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            logger.info(f"Configuração salva em: {self.config_file}")
        except IOError as e:
            logger.error(f"Erro ao salvar configuração: {e}")


def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Extrai textos de arquivos binários do Metal Gear Solid PSX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --vox                    # Processa apenas VOX.DAT do CD1
  %(prog)s --radio --face           # Processa RADIO.DAT e FACE.DAT do CD1
  %(prog)s --cd CD2 --vox           # Processa VOX.DAT do CD2
  %(prog)s --list                   # Lista arquivos disponíveis
  %(prog)s --all                    # Processa todos os arquivos padrão
  %(prog)s --cd CD1 --all           # Processa todos os arquivos do CD1
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
    
    # Grupo para seleção de arquivos
    file_group = parser.add_argument_group('Seleção de arquivos')
    file_group.add_argument(
        "--list", 
        action="store_true",
        help="Lista arquivos disponíveis e sai"
    )
    
    file_group.add_argument(
        "--all", 
        action="store_true",
        help="Processa todos os arquivos padrão"
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
            help=f"Processa {file_descriptions[file_key]}"
        )
    
    # Argumentos posicionais para compatibilidade
    parser.add_argument(
        "files", 
        nargs="*", 
        help="Caminhos de arquivos específicos (compatibilidade)"
    )
    
    # Configurações do extrator
    config_group = parser.add_argument_group('Configurações do extrator')
    config_group.add_argument(
        "--min-length", 
        type=int, 
        default=4,
        help="Comprimento mínimo do texto (padrão: 4)"
    )
    
    config_group.add_argument(
        "--max-length", 
        type=int, 
        default=1000,
        help="Comprimento máximo do texto (padrão: 1000)"
    )
    
    config_group.add_argument(
        "--encodings", 
        nargs="+",
        default=["shift_jis", "utf-8", "latin-1"],
        help="Encodings para tentar (padrão: shift_jis utf-8 latin-1)"
    )
    
    config_group.add_argument(
        "--output-dir", 
        default="extracted",
        help="Diretório de saída (padrão: extracted)"
    )
    
    config_group.add_argument(
        "--control-codes", 
        nargs="+",
        default=["#N", "#P", "#W", "#C"],
        help="Códigos de controle a tratar como delimitadores (padrão: #N #P #W #C)"
    )
    
    config_group.add_argument(
        "--skip-validation", 
        action="store_true",
        help="Pula validação de textos (captura tudo que conseguir decodificar)"
    )
    
    # Outras opções
    other_group = parser.add_argument_group('Outras opções')
    other_group.add_argument(
        "--save-config", 
        action="store_true",
        help="Salva a configuração atual"
    )
    
    other_group.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Saída detalhada"
    )
    
    other_group.add_argument(
        "--merge-translations", 
        action="store_true",
        default=True,
        help="Mescla com traduções existentes (padrão: habilitado)"
    )
    
    other_group.add_argument(
        "--no-merge-translations", 
        action="store_true",
        help="Não mescla com traduções existentes"
    )
    
    return parser


def main():
    """Função principal do script."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configura o nível de log
    if args.verbose:
        logger.setLevel(10)  # DEBUG
    
    # Gerencia arquivos
    file_manager = FileManager(args.cd)
    
    # Lista arquivos e sai se solicitado
    if args.list:
        print(f"\n Arquivos disponíveis em {args.cd}:")
        print("-" * 50)
        available = file_manager.list_available_files()
        if available:
            for line in available:
                print(f"  {line}")
        else:
            print(f"   Diretório {args.cd} não encontrado")
        print(f"\nUso: {parser.prog} --cd {args.cd} --<arquivo>")
        print(f"Exemplo: {parser.prog} --cd {args.cd} --vox --radio")
        return
    
    # Determina quais arquivos processar
    files_to_process = []
    
    if args.files:
        # Usa arquivos especificados na linha de comando (compatibilidade)
        files_to_process = [Path(f) for f in args.files]
        logger.info("Usando arquivos especificados na linha de comando")
    
    elif args.all:
        # Processa todos os arquivos padrão
        files_to_process = file_manager.get_default_files()
        logger.info(f"Processando todos os arquivos padrão do {args.cd}")
    
    else:
        # Verifica quais flags de arquivo foram especificadas
        selected_files = []
        available_files = file_manager.get_available_files()
        
        for key in available_files.keys():
            if getattr(args, key, False):
                selected_files.append(key)
        
        if selected_files:
            files_to_process = file_manager.resolve_files(selected_files)
            logger.info(f"Processando arquivos selecionados: {', '.join(selected_files)}")
        else:
            # Nenhum arquivo especificado, usa padrão
            files_to_process = file_manager.get_default_files()
            logger.info(f"Nenhum arquivo especificado, usando arquivos padrão do {args.cd}")
    
    # Valida arquivos
    valid_files = []
    for file_path in files_to_process:
        if file_path and file_path.exists():
            valid_files.append(file_path)
        else:
            logger.warning(f"Arquivo não encontrado: {file_path}")
    
    if not valid_files:
        logger.error("Nenhum arquivo válido encontrado para processar")
        logger.info(f"Use --list para ver arquivos disponíveis em {args.cd}")
        sys.exit(1)
    
    # Cria configuração do extrator
    config = TextExtractorConfig(
        min_length=args.min_length,
        max_length=args.max_length,
        encodings=args.encodings,
        output_dir=args.output_dir,
        skip_validation=args.skip_validation,
        control_codes=args.control_codes
    )
    
    # Salva configuração se solicitado
    if args.save_config:
        file_manager.save_config(valid_files, config)
    
    # Processa arquivos
    merge_translations = args.merge_translations and not args.no_merge_translations
    extractor = TextExtractor(config, merge_translations)
    total_texts = 0
    
    logger.info(f" Iniciando processamento de {len(valid_files)} arquivo(s) do {args.cd}")
    
    for file_path in valid_files:
        try:
            results = extractor.extract_texts(file_path)
            if results:
                extractor.save_results(file_path, results)
                total_texts += len(results)
                logger.info(f" {file_path.name}: {len(results)} textos extraídos")
            else:
                logger.warning(f"  {file_path.name}: Nenhum texto encontrado")
                
        except Exception as e:
            logger.error(f" Erro ao processar {file_path.name}: {e}")
            continue
    
    logger.info(f" Processamento concluído! Total: {total_texts} textos extraídos")


if __name__ == "__main__":
    main()

    """
    Exemplos de uso:

    
    python scan_texts.py --vox           # Apenas VOX.DAT
    python scan_texts.py --radio --face  # RADIO.DAT e FACE.DAT
    python scan_texts.py --brf --stage   # BRF.DAT e STAGE.DIR

    python scan_texts.py --cd CD1 --vox  # VOX.DAT do CD1
    python scan_texts.py --cd CD2 --vox  # VOX.DAT do CD2

    # listagem de arquivos disponiveis
    python scan_texts.py --list
    python scan_texts.py --cd CD1 --list

    # novos parametros
    python scan_texts.py --all           # Todos os arquivos padrão
    python scan_texts.py --cd CD2 --all  # Todos do CD2 

    # exemplos gerais

    # Analisar apenas o VOX.DAT
    python scan_texts.py --vox

    # Analisar RADIO e FACE do CD1
    python scan_texts.py --radio --face

    # Ver arquivos disponíveis
    python scan_texts.py --list

    # Processar tudo do CD1
    python scan_texts.py --all

    # Especificar CD2 (quando tiver)
    python scan_texts.py --cd CD2 --vox

    # Manter compatibilidade com versão anterior
    python scan_texts.py caminho/para/arquivo.dat       

    """