#!/usr/bin/env python3
"""
Configuração centralizada — MGS PSX Tradução PT-BR
===================================================
Fonte única da verdade para FILE_MAPPING, caminhos e estratégias.

Estrutura esperada do projeto:
    /
    ├── main.py
    ├── config.py
    ├── .env
    ├── util/
    │   └── logger_config.py
    ├── tools/
    │   ├── scan_texts.py
    │   ├── rebuild_text.py
    │   ├── overflow_checker.py
    │   ├── offset_analyzer.py
    │   ├── offset_finder.py
    │   └── extracted_filter.py
    ├── assets/fontes/CD1/   <- arquivos originais (configurável via .env)
    ├── assets/fontes/CD2/
    ├── extracted/           <- CSVs extraídos (criado automaticamente)
    ├── translated/          <- CSVs com traduções
    ├── output/              <- arquivos patcheados e relatórios
    └── patches/

Para apontar os CDs para outro local, crie um .env na raiz:
    CD1_PATH=/media/mgs_cd1
    CD2_PATH=/media/mgs_cd2
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Raiz do projeto — config.py sempre fica na raiz
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent.absolute()

# ---------------------------------------------------------------------------
# Leitura do .env (sem dependência de python-dotenv)
# ---------------------------------------------------------------------------

def _load_env_file():
    """Carrega variáveis de um arquivo .env na raiz do projeto, se existir."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

_load_env_file()

# ---------------------------------------------------------------------------
# Caminhos dos CDs (configuráveis via .env ou variável de ambiente)
# ---------------------------------------------------------------------------
CD_PATHS: dict[str, Path] = {
    "CD1": Path(os.environ.get("CD1_PATH", str(BASE_DIR / "assets" / "fontes" / "CD1"))),
    "CD2": Path(os.environ.get("CD2_PATH", str(BASE_DIR / "assets" / "fontes" / "CD2"))),
}

# Pasta onde ficam os scripts de ferramentas
TOOLS_DIR = BASE_DIR / "tools"

# ---------------------------------------------------------------------------
# Diretórios de trabalho — criados automaticamente na importação
# ---------------------------------------------------------------------------
DIRS = {
    "extracted":  BASE_DIR / "extracted",
    "translated": BASE_DIR / "translated",
    "output":     BASE_DIR / "output",
    "patches":    BASE_DIR / "patches",
}

for _d in DIRS.values():
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Mapeamento de arquivos por CD  <- fonte única da verdade
# Os scripts em tools/ devem importar daqui em vez de redefinir localmente.
# ---------------------------------------------------------------------------
FILE_MAPPING: dict[str, dict[str, str]] = {
    "CD1": {
        "radio":  "RADIO.DAT",
        "brf":    "BRF.DAT",
        "stage":  "STAGE.DIR",
        "face":   "FACE.DAT",
        "demo":   "DEMO.DAT",
        "vox":    "VOX.DAT",
        "slus":   "SLUS_005.94",
        "zmovie": "ZMOVIE.STR",
    },
    "CD2": {
        "radio":  "RADIO.DAT",
        "brf":    "BRF.DAT",
        "stage":  "STAGE.DIR",
        "face":   "FACE.DAT",
        "demo":   "DEMO.DAT",
        "vox":    "VOX.DAT",
        "zmovie": "ZMOVIE.STR",
    },
}

# Arquivos processados quando nenhuma flag específica é passada
DEFAULT_FILES = ["radio", "brf", "stage", "face", "demo", "vox"]

# ---------------------------------------------------------------------------
# Estratégias de rebuild por nome de arquivo (usado por rebuild_text.py)
# ---------------------------------------------------------------------------
FILE_STRATEGIES: dict[str, str] = {
    "STAGE.DIR":   "stage_strategy",
    "RADIO.DAT":   "generic_strategy",
    "DEMO.DAT":    "generic_strategy",
    "VOX.DAT":     "generic_strategy",
    "ZMOVIE.STR":  "generic_strategy",
    "BRF.DAT":     "generic_strategy",
    "FACE.DAT":    "generic_strategy",
}

# ---------------------------------------------------------------------------
# Códigos de controle do codec MGS usados como delimitadores na extração
# ---------------------------------------------------------------------------
CONTROL_CODES = ["#N", "#P", "#W", "#C", "#K", "#E", "#S", "#T"]

# ---------------------------------------------------------------------------
# Helpers de caminho
# Use estas funções nos scripts — não construa Path() manualmente.
# ---------------------------------------------------------------------------

def get_original_path(cd: str, file_key: str) -> Path | None:
    """
    Retorna o Path do arquivo original no CD, ou None se não existir.

        get_original_path("CD1", "vox")  →  .../assets/fontes/CD1/VOX.DAT
    """
    filename = FILE_MAPPING.get(cd, {}).get(file_key)
    if not filename:
        return None
    path = CD_PATHS[cd] / filename
    return path if path.exists() else None


def get_extracted_path(cd: str, file_key: str) -> Path:
    """
    Retorna o Path do CSV extraído (pode ainda não existir).

        get_extracted_path("CD1", "vox")  →  .../extracted/CD1/strings_VOX.csv
    """
    filename = FILE_MAPPING.get(cd, {}).get(file_key, file_key.upper())
    stem = Path(filename).stem
    out_dir = DIRS["extracted"] / cd
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"strings_{stem}.csv"


def get_translated_path(cd: str, file_key: str) -> Path:
    """
    Retorna o Path do CSV traduzido (pode ainda não existir).

        get_translated_path("CD1", "vox")  →  .../translated/CD1/strings_VOX_traduzido.csv
    """
    filename = FILE_MAPPING.get(cd, {}).get(file_key, file_key.upper())
    stem = Path(filename).stem
    out_dir = DIRS["translated"] / cd
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"strings_{stem}_traduzido.csv"


def get_output_path(cd: str, file_key: str) -> Path:
    """
    Retorna o Path do arquivo binário patcheado.

        get_output_path("CD1", "vox")  →  .../output/CD1/VOX_PATCHED.DAT
    """
    filename = FILE_MAPPING.get(cd, {}).get(file_key, file_key.upper())
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    out_dir = DIRS["output"] / cd
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{stem}_PATCHED{suffix}"


def get_overflow_report_path(cd: str, file_key: str) -> Path:
    """Retorna o Path do relatório de overflow (.xlsx)."""
    filename = FILE_MAPPING.get(cd, {}).get(file_key, file_key.upper())
    stem = Path(filename).stem
    out_dir = DIRS["output"] / cd
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"overflow_{stem}.xlsx"


def list_available_files(cd: str) -> list[tuple[str, str, bool]]:
    """
    Lista arquivos de um CD como (chave, nome_do_arquivo, existe_no_disco).
    """
    result = []
    for key, filename in FILE_MAPPING.get(cd, {}).items():
        path = CD_PATHS.get(cd, Path()) / filename
        result.append((key, filename, path.exists()))
    return result


def resolve_file_keys(cd: str, keys: list[str]) -> list[str]:
    """
    Filtra e retorna apenas chaves válidas para o CD informado.
    Imprime aviso para chaves não reconhecidas.
    """
    available = FILE_MAPPING.get(cd, {})
    valid = []
    for key in keys:
        if key in available:
            valid.append(key)
        else:
            print(f"Chave '{key}' não reconhecida para {cd} — ignorando.")
    return valid
