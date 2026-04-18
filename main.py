#!/usr/bin/env python3
"""
MGS PSX — Ferramentas de Tradução PT-BR
========================================
Ponto de entrada unificado. Delega para os scripts em tools/ via subprocess,
mantendo o isolamento de cada ferramenta e evitando conflitos de sys.path.

Uso:
    python main.py <comando> [opções]

Comandos:
    info        Lista arquivos disponíveis por CD
    extract     Extrai textos dos arquivos .DAT/.DIR
    rebuild     Aplica traduções e gera arquivos patcheados
    check       Verifica overflows nas traduções
    analyze     Inspeciona offsets após patch
    find        Busca offset de um texto no binário
    filter      Filtra CSV de extrações por lista de offsets
    pipeline    Executa extract -> check -> rebuild em sequência

Exemplos:
    python main.py info --cd CD1
    python main.py extract --cd CD1 --vox --radio
    python main.py extract --cd CD1 --all
    python main.py check --cd CD1 --stage
    python main.py rebuild --cd CD1 --vox
    python main.py rebuild --cd CD2 --all
    python main.py pipeline --cd CD1 --all
    python main.py pipeline --cd CD1 --vox --skip-check
    python main.py analyze --cd CD1 vox 0x1fc 0x24c
    python main.py analyze --cd CD1 --patched vox 0x1fc
    python main.py find --cd CD1 vox "Snake"
    python main.py filter offsets.txt extracted/CD1/strings_VOX.csv
"""

import sys
import subprocess
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BASE_DIR))

import config as cfg


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _run(script: str, extra_args: list[str]) -> int:
    """Executa um script em tools/ como subprocesso e retorna o exit code."""
    script_path = cfg.TOOLS_DIR / script
    cmd = [sys.executable, str(script_path)] + extra_args
    result = subprocess.run(cmd)
    return result.returncode


def _add_cd_arg(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--cd",
        choices=list(cfg.FILE_MAPPING.keys()),
        default="CD1",
        help="CD a processar (padrão: CD1)",
    )


def _add_file_flags(parser: argparse.ArgumentParser):
    """Adiciona --all e uma flag --<chave> para cada arquivo do mapeamento."""
    parser.add_argument("--all", action="store_true", help="Processa todos os arquivos padrão")
    all_keys = set()
    for mapping in cfg.FILE_MAPPING.values():
        all_keys.update(mapping.keys())
    for key in sorted(all_keys):
        parser.add_argument(f"--{key}", action="store_true", dest=key)


def _selected_keys(args: argparse.Namespace) -> list[str]:
    """Retorna as chaves de arquivo selecionadas pelo usuário."""
    if getattr(args, "all", False):
        return cfg.DEFAULT_FILES
    keys = [k for k in cfg.FILE_MAPPING.get(args.cd, {}) if getattr(args, k, False)]
    if not keys:
        print("Nenhum arquivo especificado — usando arquivos padrão.")
        keys = cfg.DEFAULT_FILES
    return keys


def _file_flags_from_keys(keys: list[str]) -> list[str]:
    """Converte lista de chaves em flags de linha de comando (ex: ["vox"] -> ["--vox"])."""
    return [f"--{k}" for k in keys]


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

def cmd_info(args):
    files = cfg.list_available_files(args.cd)
    print(f"\n  Arquivos em {args.cd}  ({cfg.CD_PATHS[args.cd]})")
    print("-" * 60)
    for key, filename, exists in files:
        status = "OK" if exists else "X  não encontrado"
        print(f"  --{key:<10}  {filename:<20}  {status}")
    print()
    if not any(e for _, _, e in files):
        print(f"  Nenhum arquivo encontrado. Configure CD1_PATH/CD2_PATH no .env")
    print()


def build_info_parser(sub):
    p = sub.add_parser("info", help="Lista arquivos disponíveis por CD")
    _add_cd_arg(p)
    return p

# ---------------------------------------------------------------------------
# extract  ->  tools/scan_texts.py
# ---------------------------------------------------------------------------

def cmd_extract(args):
    keys = _selected_keys(args)
    extra = ["--cd", args.cd] + _file_flags_from_keys(keys)
    if getattr(args, "skip_validation", False):
        extra.append("--skip-validation")
    if getattr(args, "no_merge", False):
        extra.append("--no-merge-translations")
    if getattr(args, "verbose", False):
        extra.append("--verbose")
    rc = _run("scan_texts.py", extra)
    sys.exit(rc) if rc != 0 else None


def build_extract_parser(sub):
    p = sub.add_parser("extract", help="Extrai textos dos arquivos .DAT/.DIR")
    _add_cd_arg(p)
    _add_file_flags(p)
    p.add_argument("--skip-validation", action="store_true",
                   help="Captura tudo sem validar se é texto legível")
    p.add_argument("--no-merge", action="store_true",
                   help="Não mescla com traduções existentes")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


# ---------------------------------------------------------------------------
# check  ->  tools/overflow_checker.py
# ---------------------------------------------------------------------------

def cmd_check(args):
    keys = _selected_keys(args)
    for key in keys:
        csv_path = cfg.get_translated_path(args.cd, key)
        if not csv_path.exists():
            print(f"  CSV traduzido não encontrado: {csv_path.relative_to(BASE_DIR)} — pulando.")
            continue
        out_path = cfg.get_overflow_report_path(args.cd, key)
        print(f"\n  {key.upper()} -> {csv_path.name}")
        rc = _run("overflow_checker.py", ["--cd", args.cd, "--file", str(csv_path), "-o", str(out_path)])
        if rc == 0:
            print(f"  Relatório: {out_path.relative_to(BASE_DIR)}")
        else:
            print(f"  Erro ao verificar {key}.")


def build_check_parser(sub):
    p = sub.add_parser("check", help="Verifica overflows nas traduções")
    _add_cd_arg(p)
    _add_file_flags(p)
    return p


# ---------------------------------------------------------------------------
# rebuild  ->  tools/rebuild_text.py
# ---------------------------------------------------------------------------

def cmd_rebuild(args):
    keys = _selected_keys(args)
    for key in keys:
        extra = ["--cd", args.cd, f"--{key}"]
        if getattr(args, "debug", False):
            extra.append("--debug")
        if getattr(args, "no_strict", False):
            extra.append("--no-strict")
        print(f"\n  Reconstruindo {key.upper()} ({args.cd})...")
        rc = _run("rebuild_text.py", extra)
        if rc != 0:
            print(f"  Falha ao reconstruir {key}.")


def build_rebuild_parser(sub):
    p = sub.add_parser("rebuild", help="Aplica traduções e gera arquivos patcheados")
    _add_cd_arg(p)
    _add_file_flags(p)
    p.add_argument("--debug", action="store_true", help="Modo debug detalhado")
    p.add_argument("--no-strict", action="store_true", dest="no_strict",
                   help="Desativa modo estrito de validação de tamanho")
    return p


# ---------------------------------------------------------------------------
# analyze  ->  tools/offset_analyzer.py
# ---------------------------------------------------------------------------

def cmd_analyze(args):
    extra = ["--cd", args.cd, f"--{args.file}"]
    if getattr(args, "use_patched", False):
        extra += ["--use-patched", str(cfg.get_output_path(args.cd, args.file))]
    extra += ["--offsets"] + args.offsets
    rc = _run("offset_analyzer.py", extra)
    sys.exit(rc) if rc != 0 else None


def build_analyze_parser(sub):
    p = sub.add_parser("analyze", help="Inspeciona offsets num arquivo binário")
    _add_cd_arg(p)
    p.add_argument("file", help="Chave do arquivo (ex: vox, radio, stage)")
    p.add_argument("offsets", nargs="+",
                   help="Offsets em hex para inspecionar (ex: 0x1fc 0x24c)")
    p.add_argument("--patched", action="store_true", dest="use_patched",
                   help="Analisa o arquivo patcheado em vez do original")
    return p


# ---------------------------------------------------------------------------
# find  ->  tools/offset_finder.py
# ---------------------------------------------------------------------------

def cmd_find(args):
    extra = ["--cd", args.cd, f"--{args.file}", "--text", args.text]
    rc = _run("offset_finder.py", extra)
    sys.exit(rc) if rc != 0 else None


def build_find_parser(sub):
    p = sub.add_parser("find", help="Busca offset de um texto no arquivo binário")
    _add_cd_arg(p)
    p.add_argument("file", help="Chave do arquivo (ex: vox, radio)")
    p.add_argument("text", help="Texto para localizar")
    return p


# ---------------------------------------------------------------------------
# filter  ->  tools/extracted_filter.py
# ---------------------------------------------------------------------------

def cmd_filter(args):
    extra = [args.offsets_txt, args.csv]
    if args.output:
        extra.append(args.output)
    rc = _run("extracted_filter.py", extra)
    sys.exit(rc) if rc != 0 else None


def build_filter_parser(sub):
    p = sub.add_parser("filter", help="Filtra CSV extraído por lista de offsets")
    p.add_argument("offsets_txt", help="Arquivo .txt com um offset por linha")
    p.add_argument("csv", help="CSV de textos extraídos")
    p.add_argument("--output", "-o", help="Arquivo de saída (opcional)")
    return p


# ---------------------------------------------------------------------------
# pipeline  (extract -> check -> rebuild)
# ---------------------------------------------------------------------------

def cmd_pipeline(args):
    print("=" * 56)
    print(f"  Pipeline completo — {args.cd}")
    print("=" * 56)

    step = 1

    if not args.skip_extract:
        print(f"\n[{step}/3]   Extração de textos")
        cmd_extract(args)
    else:
        print(f"\n[{step}/3]    Extração ignorada (--skip-extract)")
    step += 1

    if not args.skip_check:
        print(f"\n[{step}/3]   Verificação de overflows")
        cmd_check(args)
    else:
        print(f"\n[{step}/3]    Verificação ignorada (--skip-check)")
    step += 1

    if not args.skip_rebuild:
        print(f"\n[{step}/3]   Reconstrução (patch)")
        cmd_rebuild(args)
    else:
        print(f"\n[{step}/3]    Rebuild ignorado (--skip-rebuild)")

    print("\n" + "=" * 56)
    print("🏁  Pipeline concluído!")
    print("=" * 56)


def build_pipeline_parser(sub):
    p = sub.add_parser("pipeline",
                       help="Executa extract -> check -> rebuild em sequência")
    _add_cd_arg(p)
    _add_file_flags(p)
    # Flags herdadas de cada etapa
    p.add_argument("--skip-validation", action="store_true")
    p.add_argument("--no-merge", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--no-strict", action="store_true", dest="no_strict")
    # Pular etapas
    p.add_argument("--skip-extract",  action="store_true",
                   help="Pula a extração")
    p.add_argument("--skip-check",    action="store_true",
                   help="Pula a verificação de overflow")
    p.add_argument("--skip-rebuild",  action="store_true",
                   help="Pula o rebuild")
    return p


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="MGS PSX — Ferramentas de Tradução PT-BR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", metavar="<comando>")
    sub.required = True

    build_info_parser(sub)
    build_extract_parser(sub)
    build_check_parser(sub)
    build_rebuild_parser(sub)
    build_analyze_parser(sub)
    build_find_parser(sub)
    build_filter_parser(sub)
    build_pipeline_parser(sub)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "info":     cmd_info,
        "extract":  cmd_extract,
        "check":    cmd_check,
        "rebuild":  cmd_rebuild,
        "analyze":  cmd_analyze,
        "find":     cmd_find,
        "filter":   cmd_filter,
        "pipeline": cmd_pipeline,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()