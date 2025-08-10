#!/usr/bin/env python3
"""
Script para filtrar CSV de textos extraídos baseado em lista de offsets.

Offsets de interesse extraidos a partir de:

https://gist.githubusercontent.com/infernocloud/99ea49fefa60685a79f5/raw/7e26ad8973df53459f4a5d910aec4289be6b532d/metal-gear-solid-playstation-text-dump.txt

"""

import sys
import csv
from pathlib import Path
from typing import Set, List

def load_offsets_from_txt(txt_file: str) -> Set[str]:
    """
    Carrega offsets de um arquivo TXT.
    
    Args:
        txt_file: Caminho do arquivo TXT com offsets
        
    Returns:
        Set com offsets normalizados
    """
    offsets = set()
    
    try:
        with open(txt_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Pula linhas vazias ou comentários
                if not line or line.startswith('#'):
                    continue
                
                # Normaliza o offset
                try:
                    # Remove espaços e converte para lowercase
                    clean_offset = line.strip().lower()
                    
                    # Se não começar com 0x, adiciona
                    if not clean_offset.startswith('0x'):
                        # Tenta interpretar como hex sem prefixo
                        int(clean_offset, 16)  # Valida se é hex válido
                        clean_offset = '0x' + clean_offset
                    else:
                        # Valida se é hex válido
                        int(clean_offset, 16)
                    
                    offsets.add(clean_offset)
                    
                except ValueError:
                    print(f"⚠️ Linha {line_num}: '{line}' não é um offset válido - ignorando")
                    continue
                    
    except FileNotFoundError:
        print(f"❌ Arquivo não encontrado: {txt_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro ao ler arquivo {txt_file}: {e}")
        sys.exit(1)
    
    print(f" Carregados {len(offsets)} offsets únicos de {txt_file}")
    return offsets

def filter_csv_by_offsets(csv_file: str, target_offsets: Set[str], output_file: str = None) -> int:
    """
    Filtra CSV mantendo apenas linhas com offsets específicos.
    
    Args:
        csv_file: Caminho do arquivo CSV
        target_offsets: Set de offsets para manter
        output_file: Arquivo de saída (opcional)
        
    Returns:
        Número de linhas mantidas
    """
    
    if not Path(csv_file).exists():
        print(f" Arquivo CSV não encontrado: {csv_file}")
        sys.exit(1)
    
    # Define arquivo de saída
    if output_file is None:
        csv_path = Path(csv_file)
        output_file = csv_path.parent / f"{csv_path.stem}_filtrado{csv_path.suffix}"
    
    matched_rows = []
    total_rows = 0
    header = None
    
    try:
        # Lê o CSV original
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            
            # Lê o cabeçalho
            header = next(reader)
            
            # Processa cada linha
            for row in reader:
                total_rows += 1
                
                if not row:  # Pula linhas vazias
                    continue
                
                # Primeiro campo deve ser o offset
                csv_offset = row[0].strip().lower()
                
                # Normaliza offset do CSV se necessário
                if not csv_offset.startswith('0x') and csv_offset:
                    try:
                        # Tenta interpretar como hex e adicionar 0x
                        int(csv_offset, 16)
                        csv_offset = '0x' + csv_offset
                    except ValueError:
                        # Se não conseguir, mantém como está
                        pass
                
                # Verifica se offset está na lista target
                if csv_offset in target_offsets:
                    matched_rows.append(row)
                    print(f"✓ Match: {csv_offset} -> {row[1][:50] if len(row) > 1 else 'N/A'}...")
        
        # Salva CSV filtrado
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Escreve cabeçalho
            if header:
                writer.writerow(header)
            
            # Escreve linhas filtradas
            for row in matched_rows:
                writer.writerow(row)
        
        print(f"\n RESULTADO:")
        print(f"  Total de linhas no CSV original: {total_rows}")
        print(f"  Offsets alvo: {len(target_offsets)}")
        print(f"  Linhas mantidas: {len(matched_rows)}")
        print(f"  Taxa de match: {len(matched_rows)/len(target_offsets)*100:.1f}%")
        print(f" Arquivo filtrado salvo: {output_file}")
        
        # Mostra offsets não encontrados
        found_offsets = {row[0].strip().lower() for row in matched_rows}
        missing_offsets = target_offsets - found_offsets
        
        if missing_offsets:
            print(f"\n OFFSETS NÃO ENCONTRADOS ({len(missing_offsets)}):")
            for offset in sorted(missing_offsets):
                print(f"  {offset}")
        
        return len(matched_rows)
        
    except Exception as e:
        print(f" Erro ao processar CSV: {e}")
        sys.exit(1)

def create_sample_offsets_file(filename: str = "offsets_exemplo.txt"):
    """Cria arquivo de exemplo com offsets."""
    sample_offsets = [
        "# Lista de offsets para filtrar",
        "# Formato: um offset por linha",
        "# Pode usar com ou sem prefixo 0x",
        "",
        "0x1fc",
        "0x24c", 
        "0x278",
        "24c",      # Exemplo sem 0x
        "278",      # Exemplo sem 0x
        "",
        "# Offsets maiores:",
        "0x64495c",
        "0x644998",
        "0x7a8120"
    ]
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sample_offsets))
        print(f" Arquivo de exemplo criado: {filename}")
    except Exception as e:
        print(f" Erro ao criar arquivo de exemplo: {e}")

def main():
    """Função principal."""
    
    if len(sys.argv) < 3:
        print("FILTRADOR DE CSV POR OFFSETS")
        print("=" * 30)
        print("Uso: python csv_offset_filter.py <offsets.txt> <textos.csv> [saida.csv]")
        print()
        print("Parâmetros:")
        print("  offsets.txt  - Arquivo TXT com lista de offsets (um por linha)")
        print("  textos.csv   - Arquivo CSV com textos extraídos")
        print("  saida.csv    - Arquivo de saída (opcional)")
        print()
        print("Exemplos:")
        print("  python csv_offset_filter.py offsets.txt strings_STAGE.csv")
        print("  python csv_offset_filter.py lista_offsets.txt strings_STAGE.csv resultado.csv")
        print()
        
        # Pergunta se quer criar arquivo de exemplo
        response = input("Criar arquivo de exemplo? (s/n): ").lower().strip()
        if response in ['s', 'sim', 'y', 'yes']:
            create_sample_offsets_file()
        
        sys.exit(1)
    
    txt_file = sys.argv[1]
    csv_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    print(" FILTRADOR DE CSV POR OFFSETS")
    print("=" * 40)
    print(f" Arquivo de offsets: {txt_file}")
    print(f" Arquivo CSV: {csv_file}")
    print(f" Arquivo de saída: {output_file or 'auto-gerado'}")
    print()
    
    # Carrega offsets do TXT
    target_offsets = load_offsets_from_txt(txt_file)
    
    if not target_offsets:
        print(" Nenhum offset válido encontrado no arquivo TXT")
        sys.exit(1)
    
    # Filtra CSV
    matched_count = filter_csv_by_offsets(csv_file, target_offsets, output_file)
    
    if matched_count == 0:
        print("\n Nenhum offset foi encontrado no CSV!")
        print("Verifique se:")
        print("- Os offsets estão no formato correto (ex: 0x1fc)")
        print("- O CSV tem offsets na primeira coluna")
        print("- Os offsets no TXT correspondem aos do CSV")
    else:
        print(f"\n Filtração concluída com sucesso!")
        print(f"CSV filtrado contém {matched_count} textos selecionados.")

if __name__ == "__main__":
    main()