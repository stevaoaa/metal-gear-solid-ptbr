import os
import sys
import unicodedata
import pandas as pd

# Adiciona o diretório raiz ao sys.path para permitir importações internas
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger

# Inicializa o logger para registrar as operações do script
logger = setup_logger()

# Caminhos para os arquivos envolvidos no processo
ARQUIVO_ORIGINAL = "./assets/fontes/CD1/RADIO.DAT"
ARQUIVO_CSV = "./translated/strings_RADIO_traduzido.csv"
ARQUIVO_SAIDA = "./patches/RADIO_PATCHED.DAT"  # Novo caminho para o patch

# Codificação usada no jogo (PlayStation 1 japonês)
ENCODING = "shift_jis"

def remover_acentos(texto: str) -> str:
    """
    Remove acentos e caracteres especiais do texto, convertendo para ASCII puro.
    Isso ajuda a manter compatibilidade com a codificação Shift_JIS e evita quebra de layout no jogo.
    """
    return unicodedata.normalize('NFKD', texto).encode('ASCII', 'ignore').decode('ASCII')

def substituir_textos(bin_path, csv_path, saida_path):
    """
    Substitui os textos no arquivo binário original com os textos traduzidos
    respeitando os limites de tamanho e codificação.
    """
    # Lê o arquivo binário original para um array de bytes mutável
    with open(bin_path, "rb") as f:
        bin_data = bytearray(f.read())

    # Carrega as traduções do CSV
    df = pd.read_csv(csv_path)

    # Contadores para estatísticas
    alteracoes = 0
    erros_codificacao = 0
    erros_tamanho = 0

    # Processa linha por linha do CSV
    for _, row in df.iterrows():
        offset = int(row["offset"], 16)
        texto_original = str(row["texto"])
        texto_traduzido = str(row["texto_traduzido"]).strip()

        # Ignora entradas sem tradução
        if not texto_traduzido:
            continue

        # Remove acentos e normaliza para caracteres compatíveis
        texto_traduzido_normalizado = remover_acentos(texto_traduzido)

        try:
            # Codifica os textos para bytes usando Shift_JIS
            bytes_original = texto_original.encode(ENCODING)
            bytes_novo = texto_traduzido_normalizado.encode(ENCODING)
        except Exception as e:
            # Se houver erro de codificação, ignora esta entrada
            logger.info(f"Erro ao codificar tradução: {texto_traduzido} -> {e}")
            erros_codificacao += 1
            continue

        # Verifica se a tradução cabe no espaço original
        if len(bytes_novo) > len(bytes_original):
            logger.error(f"Tradução maior que espaço disponível em {hex(offset)}: \"{texto_traduzido}\"")
            erros_tamanho += 1
            continue

        # Preenche o espaço restante com zeros (padding)
        padding = b"\x00" * (len(bytes_original) - len(bytes_novo))

        # Substitui os bytes diretamente no buffer do arquivo
        bin_data[offset : offset + len(bytes_original)] = bytes_novo + padding
        alteracoes += 1

    # Garante que a pasta de saída exista
    os.makedirs(os.path.dirname(saida_path), exist_ok=True)

    # Salva o novo arquivo binário com as traduções aplicadas
    with open(saida_path, "wb") as f:
        f.write(bin_data)

    # Log das estatísticas da operação
    logger.info(f"\nArquivo salvo em: {saida_path}")
    logger.info(f"Textos substituídos: {alteracoes}")
    logger.info(f"Traduções ignoradas por erro de codificação: {erros_codificacao}")
    logger.info(f"Traduções ignoradas (maiores que o original): {erros_tamanho}")

if __name__ == "__main__":
    # Executa a substituição somente se os arquivos necessários existirem
    if not os.path.exists(ARQUIVO_CSV) or not os.path.exists(ARQUIVO_ORIGINAL):
        logger.info("Arquivo CSV ou binário não encontrado.")
    else:
        substituir_textos(ARQUIVO_ORIGINAL, ARQUIVO_CSV, ARQUIVO_SAIDA)