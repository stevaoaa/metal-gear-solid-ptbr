import os
import sys
import requests
import time
import random
from datetime import datetime, timedelta
from threading import Lock

# Adiciona o diretório pai ao sys.path para permitir importações relativas
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger

# Carrega variáveis de ambiente do arquivo .env
from dotenv import load_dotenv
load_dotenv()

# Inicializa o logger personalizado
logger = setup_logger()

class LocalRateLimiter:
    """
    Rate limiter mais simples para modelos locais.
    Foca em não sobrecarregar o hardware local.
    """
    
    def __init__(self, requests_per_minute=60, delay_between_requests=0.5):
        self.requests_per_minute = requests_per_minute
        self.delay_between_requests = delay_between_requests  # Delay mínimo entre requisições
        self.request_history = []
        self.last_request_time = 0
        self.lock = Lock()
        
        logger.info(f"Rate Limiter local configurado: {requests_per_minute}/min, delay mínimo: {delay_between_requests}s")
    
    def aguardar_se_necessario(self):
        """Aplica rate limiting baseado em tempo mínimo entre requisições e limite por minuto"""
        with self.lock:
            agora = time.time()
            
            # Delay mínimo entre requisições (para não sobrecarregar)
            if self.last_request_time > 0:
                tempo_desde_ultima = agora - self.last_request_time
                if tempo_desde_ultima < self.delay_between_requests:
                    espera = self.delay_between_requests - tempo_desde_ultima
                    logger.debug(f"Aplicando delay mínimo: {espera:.2f}s")
                    time.sleep(espera)
                    agora = time.time()
            
            # Limpa histórico antigo (> 1 minuto)
            limite_tempo = agora - 60
            self.request_history = [req_time for req_time in self.request_history if req_time > limite_tempo]
            
            # Verifica limite por minuto
            if len(self.request_history) >= self.requests_per_minute:
                tempo_espera = 60 - (agora - self.request_history[0]) + 0.1
                if tempo_espera > 0:
                    logger.debug(f"Rate limit por minuto: aguardando {tempo_espera:.1f}s")
                    time.sleep(tempo_espera)
            
            return 0
    
    def registrar_request(self):
        """Registra uma nova requisição"""
        with self.lock:
            agora = time.time()
            self.request_history.append(agora)
            self.last_request_time = agora
    
    def obter_status(self):
        """Retorna status atual"""
        with self.lock:
            agora = time.time()
            limite_tempo = agora - 60
            requests_ultimo_minuto = len([req for req in self.request_history if req > limite_tempo])
            
            return {
                'requests_ultimo_minuto': requests_ultimo_minuto,
                'limite_minuto': self.requests_per_minute,
                'delay_entre_requests': self.delay_between_requests
            }


class LMStudioClient:
    def __init__(self, base_url=None, modelo=None, rate_limit_config=None):
        # Configuração da URL base (padrão do LM Studio)
        self.base_url = base_url or os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234")
        self.api_url = f"{self.base_url}/v1/chat/completions"
        
        # O LM Studio normalmente não precisa de API key, mas permite configurar
        self.api_key = os.getenv("LMSTUDIO_API_KEY", "not-needed")
        
        # Modelo (pode ser definido ou autodetectado)
        self.modelo = modelo or os.getenv("LMSTUDIO_MODEL", "local-model")
        
        # Configuração de rate limiting para modelos locais
        if rate_limit_config is None:
            rate_limit_config = self._detectar_configuracao_rate_limit()
        
        self.rate_limiter = LocalRateLimiter(**rate_limit_config)

        logger.info("Utilizando LM Studio API local.")
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"Modelo: {self.modelo}")
        logger.info(f"Endpoint: {self.api_url}")
    
    def _detectar_configuracao_rate_limit(self):
        """Detecta configuração otimizada para hardware local"""
        modo = os.getenv("LMSTUDIO_MODE", "balanced").lower()
        
        configuracoes = {
            "fast": {
                "requests_per_minute": 120,    # Máxima velocidade
                "delay_between_requests": 0.2  # 200ms entre requests
            },
            "balanced": {
                "requests_per_minute": 60,     # Velocidade equilibrada
                "delay_between_requests": 0.5  # 500ms entre requests
            },
            "conservative": {
                "requests_per_minute": 30,     # Mais devagar, preserva hardware
                "delay_between_requests": 1.0  # 1s entre requests
            },
            "custom": {
                "requests_per_minute": int(os.getenv("LMSTUDIO_RPM", 60)),
                "delay_between_requests": float(os.getenv("LMSTUDIO_DELAY", 0.5))
            }
        }
        
        config = configuracoes.get(modo, configuracoes["balanced"])
        logger.info(f"Modo LM Studio '{modo}': {config}")
        return config
    
    def calcular_tamanho_bytes(self, texto):
        """Calcula o tamanho em bytes do texto usando codificação UTF-8"""
        return len(str(texto).encode('utf-8'))
    
    def testar_conexao(self):
        """Testa a conexão com o LM Studio"""
        try:
            # Tenta listar modelos primeiro
            models_url = f"{self.base_url}/v1/models"
            response = requests.get(models_url, timeout=5)
            
            if response.status_code == 200:
                models_data = response.json()
                if 'data' in models_data and models_data['data']:
                    available_models = [model['id'] for model in models_data['data']]
                    logger.info(f"Modelos disponíveis: {available_models}")
                    # Atualiza o modelo se encontrar um específico
                    if available_models and self.modelo == "local-model":
                        self.modelo = available_models[0]
                        logger.info(f"Modelo atualizado para: {self.modelo}")
                    return True
                else:
                    logger.warning("Nenhum modelo carregado no LM Studio")
            
            # Se não conseguir listar modelos, testa diretamente
            return self._testar_requisicao_simples()
            
        except Exception as e:
            logger.warning(f"Erro ao testar conexão: {e}")
            return self._testar_requisicao_simples()
    
    def _testar_requisicao_simples(self):
        """Teste simples de requisição"""
        headers = {
            "Content-Type": "application/json"
        }
        
        # LM Studio normalmente não precisa de Authorization, mas adiciona se configurado
        if self.api_key and self.api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        data = {
            "model": self.modelo,
            "messages": [{"role": "user", "content": "Test"}],
            "max_tokens": 5,
            "temperature": 0.1
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=data, timeout=10)
            if response.status_code == 200:
                logger.info("✅ Conexão com LM Studio OK!")
                return True
            else:
                logger.error(f"❌ Erro de conexão: {response.status_code}")
                logger.error(f"Resposta: {response.text[:500]}")
                return False
        except Exception as e:
            logger.error(f"❌ Erro de conexão: {e}")
            return False

    def traduzir_texto(self, texto, contexto=None, temperatura=0.3, max_tokens=150, max_retentativas=3, tamanho_original=None):
        """
        Realiza a tradução usando LM Studio local.
        Otimizado para modelos locais com menos retries e timeouts maiores.
        """
        
        # Aplica rate limiting
        self.rate_limiter.aguardar_se_necessario()
        
        # Validação e limpeza do texto
        if not texto or not str(texto).strip():
            logger.warning("Texto vazio fornecido")
            return ""
        
        texto_limpo = str(texto).strip()
        
        # Para textos muito pequenos ou só caracteres especiais
        if len(texto_limpo) < 2 or not any(c.isalnum() for c in texto_limpo):
            logger.debug(f"Texto especial, retornando original: {texto_limpo}")
            return texto_limpo
        
        # Calcula tamanho original
        if tamanho_original is None:
            tamanho_original = self.calcular_tamanho_bytes(texto_limpo)

        # Constroi prompt otimizado para modelos locais (mais direto)
        if contexto and len(contexto) > 200:
            # Contexto simplificado para modelos locais
            sistema_msg = "Você é um tradutor de jogos. Traduza do inglês para português brasileiro mantendo o estilo de Metal Gear Solid."
        else:
            sistema_msg = contexto or "Traduza do inglês para português brasileiro:"
        
        user_msg = f"Texto ({tamanho_original}b): {texto_limpo}"

        headers = {
            "Content-Type": "application/json"
        }
        
        # Adiciona Authorization apenas se necessário
        if self.api_key and self.api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = {
            "model": self.modelo,
            "messages": [
                {"role": "system", "content": sistema_msg},
                {"role": "user", "content": user_msg}
            ],
            "temperature": temperatura,
            "max_tokens": max_tokens,
            "stream": False  # Força resposta completa
        }

        # Registra requisição
        self.rate_limiter.registrar_request()

        # Tentativas com timeout maior para modelos locais
        for tentativa in range(1, max_retentativas + 1):
            try:
                # Timeout maior para modelos locais (podem ser mais lentos)
                timeout = 60 if tentativa == 1 else 120
                
                response = requests.post(self.api_url, headers=headers, json=data, timeout=timeout)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if 'choices' in result and result['choices']:
                        traducao = result["choices"][0]["message"]["content"].strip()
                        
                        # Remove prefixos comuns de modelos locais
                        prefixos_remover = [
                            "tradução:", "resposta:", "resultado:", "português:",
                            "translation:", "answer:", "pt-br:", "português brasileiro:"
                        ]
                        
                        traducao_lower = traducao.lower()
                        for prefixo in prefixos_remover:
                            if traducao_lower.startswith(prefixo):
                                traducao = traducao[len(prefixo):].strip()
                                break
                        
                        # Log de controle de tamanho
                        tamanho_traducao = self.calcular_tamanho_bytes(traducao)
                        diferenca = tamanho_traducao - tamanho_original
                        percentual = (diferenca / tamanho_original) * 100 if tamanho_original > 0 else 0
                        
                        logger.debug(f"Original: {tamanho_original}b | Tradução: {tamanho_traducao}b | Diferença: {diferenca:+d}b ({percentual:+.1f}%)")
                        
                        return traducao
                    else:
                        logger.warning("Resposta sem 'choices'")
                        
                elif response.status_code == 400:
                    logger.warning(f"Erro 400, tentando prompt simplificado...")
                    # Prompt ainda mais simples para modelos locais
                    data_simples = {
                        "model": self.modelo,
                        "messages": [
                            {"role": "user", "content": f"Translate to Portuguese: {texto_limpo}"}
                        ],
                        "temperature": 0.1,
                        "max_tokens": min(max_tokens, 100)
                    }
                    
                    response_simples = requests.post(self.api_url, headers=headers, json=data_simples, timeout=timeout)
                    if response_simples.status_code == 200:
                        result_simples = response_simples.json()
                        if 'choices' in result_simples and result_simples['choices']:
                            traducao_simples = result_simples["choices"][0]["message"]["content"].strip()
                            logger.info(f"Prompt simplificado funcionou: {texto_limpo}")
                            return traducao_simples
                
                logger.warning(f"Tentativa {tentativa}/{max_retentativas} - Status {response.status_code}")
                if tentativa < max_retentativas:
                    time.sleep(2 ** tentativa)  # Backoff exponencial
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout na tentativa {tentativa}/{max_retentativas} (modelo local pode estar processando)")
                if tentativa < max_retentativas:
                    time.sleep(5)  # Espera maior para timeout
                    
            except requests.exceptions.ConnectionError:
                logger.error(f"Erro de conexão - LM Studio está rodando em {self.base_url}?")
                if tentativa < max_retentativas:
                    time.sleep(3)
                    
            except Exception as e:
                logger.error(f"Erro inesperado na tentativa {tentativa}: {e}")
                if tentativa < max_retentativas:
                    time.sleep(2)

        # Se todas as tentativas falharam
        logger.error(f"Falha ao traduzir após {max_retentativas} tentativas: {texto_limpo[:60]}")
        return texto_limpo  # Retorna original
    
    def obter_status_rate_limit(self):
        """Retorna status do rate limiter local"""
        return self.rate_limiter.obter_status()
    
    def obter_info_modelo(self):
        """Obtém informações sobre o modelo atual"""
        try:
            models_url = f"{self.base_url}/v1/models"
            response = requests.get(models_url, timeout=5)
            
            if response.status_code == 200:
                models_data = response.json()
                for model in models_data.get('data', []):
                    if model['id'] == self.modelo:
                        return {
                            'nome': model.get('id', 'desconhecido'),
                            'objeto': model.get('object', 'model'),
                            'proprietario': model.get('owned_by', 'local')
                        }
            
            return {'nome': self.modelo, 'status': 'conectado'}
            
        except Exception as e:
            logger.debug(f"Erro ao obter info do modelo: {e}")
            return {'nome': self.modelo, 'status': 'erro'}