import os
import sys
import pandas as pd

# Adiciona o diretório pai ao sys.path para permitir importações relativas
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger

# Inicializa o logger personalizado
logger = setup_logger()

# Caminho padrão para o arquivo CSV com as traduções
ARQUIVO_CSV = "./translated/strings_RADIO_traduzido.csv"

def preencher_padding_traducao(caminho_csv):
    """
    Substitui valores vazios ou ausentes na coluna 'texto_traduzido' com o texto original.
    Isso garante que nenhuma string fique em branco na ROM final, o que poderia quebrar o jogo.
    """

    # Verifica se o arquivo existe
    if not os.path.exists(caminho_csv):
        logger.error(f"Arquivo não encontrado: {caminho_csv}")
        return

    # Carrega o CSV em um DataFrame
    df = pd.read_csv(caminho_csv)

    # Verifica se as colunas essenciais estão presentes
    if "texto" not in df.columns or "texto_traduzido" not in df.columns:
        logger.error("O CSV deve conter as colunas 'texto' e 'texto_traduzido'")
        return

    # Identifica linhas onde o texto traduzido está ausente ou vazio
    linhas_afetadas = df["texto_traduzido"].isna() | df["texto_traduzido"].str.strip().eq("")

    # Loga quantas linhas serão corrigidas
    total = linhas_afetadas.sum()
    logger.info(f"Preenchendo {total} entradas vazias com o texto original.")

    # Preenche as células vazias da tradução com o texto original
    df.loc[linhas_afetadas, "texto_traduzido"] = df.loc[linhas_afetadas, "texto"]

    # Salva o CSV sobrescrevendo o original
    df.to_csv(caminho_csv, index=False, encoding="utf-8")
    logger.info(f"Arquivo atualizado: {caminho_csv}")

# Executa o preenchimento quando o script é chamado diretamente
if __name__ == "__main__":
    preencher_padding_traducao(ARQUIVO_CSV)
