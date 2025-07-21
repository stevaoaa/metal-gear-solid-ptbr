import os
import sys
import csv

# Caminho absoluto da raiz do projeto
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Adiciona o diretório raiz ao sys.path para permitir imports relativos
sys.path.append(BASE_DIR)
from util.logger_config import setup_logger

# Inicializa o logger para logar mensagens de informação e erro
logger = setup_logger()

# Configuração: mínimo de caracteres para considerar um texto válido
MIN_LENGTH = 4

# Caminho da pasta onde os textos extraídos serão salvos
DIR_SAIDA = os.path.join(BASE_DIR, "extracted")

# Lista de arquivos binários que serão processados
ARQUIVOS = [
    os.path.join(BASE_DIR, "assets", "fontes", "CD1", "RADIO.DAT"),
    # os.path.join(BASE_DIR, "assets", "fontes", "CD1", "STAGE.DIR"),
    # os.path.join(BASE_DIR, "assets", "fontes", "CD1", "BRF.DAT"),
]

def extrair_textos(path_bin, min_length=MIN_LENGTH):
    """
    Lê o binário especificado e tenta identificar blocos de texto codificados em Shift_JIS.
    Retorna uma lista de tuplas (offset, texto, tamanho_em_bytes).
    """
    with open(path_bin, "rb") as f:
        data = f.read()

    resultados = []
    encontrados = set()  # para evitar duplicatas
    i = 0
    tamanho_total = len(data)

    while i < tamanho_total:
        # Pula bytes nulos (delimitadores ou padding)
        if data[i] == 0x00:
            i += 1
            continue

        j = i
        # Encontra o próximo byte nulo (final da string)
        while j < tamanho_total and data[j] != 0x00:
            j += 1

        chunk = data[i:j]
        try:
            # Tenta decodificar o trecho como texto Shift_JIS
            texto = chunk.decode("shift_jis").strip()

            # Verifica se é um texto novo e suficientemente longo
            if len(texto) >= min_length and texto not in encontrados:
                tamanho_bytes = len(chunk)
                resultados.append((i, texto, tamanho_bytes))
                encontrados.add(texto)
                i = j  # pula para depois do chunk lido
                continue
        except:
            # Se falhar ao decodificar, ignora o trecho
            pass

        i += 1

    return resultados

def salvar_resultados(nome_arquivo, resultados):
    """
    Salva os textos extraídos em um arquivo CSV com offset, texto e tamanho.
    """
    nome_base = os.path.basename(nome_arquivo).replace(".DAT", "")
    caminho_saida = os.path.join(DIR_SAIDA, f"strings_{nome_base}.csv")

    os.makedirs(DIR_SAIDA, exist_ok=True)

    with open(caminho_saida, "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["offset", "texto", "tamanho_bytes"])  # cabeçalho
        for offset, texto, tamanho in resultados:
            writer.writerow([hex(offset), texto, tamanho])

    logger.info(f"{len(resultados)} textos salvos em: {caminho_saida}")

def main():
    """
    Executa a extração de todos os arquivos listados.
    """
    for path in ARQUIVOS:
        if not os.path.exists(path):
            logger.error(f"Arquivo não encontrado: {path}")
            continue

        logger.info(f"Extraindo textos de: {os.path.basename(path)}")
        resultados = extrair_textos(path)
        salvar_resultados(path, resultados)

if __name__ == "__main__":
    main()
