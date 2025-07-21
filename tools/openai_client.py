import os
import sys
import requests
import time
import random

# Adiciona o diretório pai ao sys.path para permitir importações relativas
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger

# Carrega variáveis de ambiente do arquivo .env
from dotenv import load_dotenv
load_dotenv()

# Inicializa o logger personalizado
logger = setup_logger()

class OpenRouterClient:
    def __init__(self, modelo="mistralai/mistral-7b-instruct"):
        # Obtém a chave da API a partir do arquivo .env
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY não configurada")

        # Define a URL e o modelo padrão da API
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"
        self.modelo = modelo

        logger.info("Utilizando OpenRouter API.")
        logger.info(f"Modelo selecionado: {self.modelo}")
        logger.info(f"Base URL configurada: {self.api_url}")

    def traduzir_texto(self, texto, contexto=None, temperatura=0.3, max_tokens=100, max_retentativas=5):
        """
        Realiza a tradução de um texto usando o modelo especificado via OpenRouter.
        Implementa backoff exponencial em caso de erros temporários.
        """

        # Define o prompt usado no modelo, com instrução de contexto opcional
        prompt = (contexto or "Você é um tradutor profissional de jogos.") + f"\n\n{texto.strip()}"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.modelo,
            "messages": [
                {"role": "system", "content": "Você é um tradutor profissional de jogos."},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperatura,
            "max_tokens": max_tokens
        }

        # Tenta enviar a requisição, com até `max_retentativas` em caso de falhas recuperáveis
        for tentativa in range(1, max_retentativas + 1):
            try:
                response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
                response.raise_for_status()
                result = response.json()

                # Retorna apenas o conteúdo traduzido
                return result["choices"][0]["message"]["content"].strip()

            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code

                # Para erros temporários (rate limit, gateway, etc), faz backoff exponencial
                if status_code in (429, 502, 503):
                    espera = (2 ** tentativa) + random.uniform(0.5, 1.5)
                    logger.warning(f"Tentativa {tentativa}/{max_retentativas} - Erro {status_code}. Aguardando {espera:.2f}s.")
                    time.sleep(espera)
                    continue
                else:
                    logger.error(f"Erro HTTP irreversível: {status_code} - {e}")
                    break

            except requests.exceptions.RequestException as e:
                # Erros de rede genéricos (timeout, DNS, etc)
                logger.warning(f"Tentativa {tentativa}/{max_retentativas} - Erro de conexão: {e}")
                time.sleep(2 ** tentativa)
                continue

            except Exception as e:
                # Qualquer outro erro inesperado
                logger.error(f"Erro inesperado ao traduzir: {e}")
                break

        # Caso todas as tentativas falhem, retorna o texto original
        logger.error(f"Falha ao traduzir após {max_retentativas} tentativas: {texto[:60]}")
        return texto  # Evita string vazia que pode quebrar o jogo
