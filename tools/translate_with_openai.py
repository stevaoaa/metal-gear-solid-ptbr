import os
import sys
import pandas as pd
from tqdm import tqdm
from dotenv import load_dotenv

# Carrega variáveis de ambiente a partir de .env
load_dotenv()

# Adiciona caminho da raiz do projeto ao sys.path para imports relativos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger
from openai_client import OpenRouterClient  # cliente customizado

logger = setup_logger()

# Caminhos dos arquivos de entrada e saída
ARQUIVO_ENTRADA = "./extracted/strings_RADIO.csv"
ARQUIVO_SAIDA = "./translated/strings_RADIO_traduzido.csv"

# Prompt base usado para orientar o modelo de IA
PROMPT_BASE = """
Você é um tradutor de jogos com foco em localização fiel ao original. Traduza a frase abaixo do inglês para português brasileiro, mantendo o tom e contexto típico de um jogo de espionagem como Metal Gear Solid. 
Preserve o estilo e não traduza nomes próprios como "Snake" ou "Otacon". 
Se a frase for um comando curto, preserve o formato conciso. Se o texto fornecido não for inglês, devolva o texto original.
Texto original:
"""

# Modelo AI a ser usado na API do OpenRouter
AI_MODEL = "moonshotai/kimi-k2:free"


def traduzir_csv(entrada, saida):
    """
    Lê um arquivo CSV contendo textos extraídos do jogo e traduz linha por linha com apoio de IA.

    Parâmetros:
        entrada (str): Caminho para o arquivo CSV com as colunas 'texto' e opcionalmente 'texto_traduzido'.
        saida (str): Caminho onde o arquivo com as traduções será salvo.

    Funcionamento:
        - Ignora linhas já traduzidas.
        - Usa um modelo de IA para traduzir apenas textos em inglês.
        - Aplica um prompt com instruções específicas de localização para manter o estilo do jogo.
        - Salva o resultado em um novo arquivo CSV.
        - Exibe o progresso no terminal e registra as ações em log.
    """
    client = OpenRouterClient(modelo=AI_MODEL)

    if not os.path.exists(entrada):
        logger.error(f"Arquivo de entrada não encontrado: {entrada}")
        return

    logger.info(f"Lendo arquivo de entrada: {entrada}")
    df = pd.read_csv(entrada)

    if "texto" not in df.columns:
        logger.error("Coluna 'texto' não encontrada no CSV.")
        return

    if "texto_traduzido" not in df.columns:
        df["texto_traduzido"] = ""

    total_linhas = len(df)
    linhas_pendentes = df["texto_traduzido"].isna() | df["texto_traduzido"].str.strip().eq("")
    total_para_traduzir = linhas_pendentes.sum()

    logger.info(f"Total de linhas no CSV: {total_linhas}")
    logger.info(f"Linhas pendentes de tradução: {total_para_traduzir}")

    for idx, row in tqdm(df.iterrows(), total=total_linhas, desc="Traduzindo"):
        if linhas_pendentes.iloc[idx]:
            texto_original = str(row["texto"])

            if not texto_original.strip():
                continue  # pula texto vazio

            try:
                traducao = client.traduzir_texto(texto_original, contexto=PROMPT_BASE)
                df.at[idx, "texto_traduzido"] = traducao
                logger.debug(f"{texto_original} -> {traducao}")
            except Exception as e:
                logger.error(f"Erro ao traduzir linha {idx}: {e}")
                continue

    os.makedirs(os.path.dirname(saida), exist_ok=True)
    df.to_csv(saida, index=False, encoding="utf-8")
    logger.info(f"Traduções salvas com sucesso em: {saida}")


if __name__ == "__main__":
    if not os.getenv("OPENROUTER_API_KEY"):
        logger.error("API key do OpenRouter não configurada. Defina OPENROUTER_API_KEY no .env.")
    else:
        traduzir_csv(ARQUIVO_ENTRADA, ARQUIVO_SAIDA)
