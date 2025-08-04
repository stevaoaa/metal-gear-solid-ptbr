import os
import sys
import pandas as pd
import time
from tqdm import tqdm
from dotenv import load_dotenv

# Carrega variáveis de ambiente a partir de .env
load_dotenv()

# Adiciona caminho da raiz do projeto ao sys.path para imports relativos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger
from lmstudio_client import LMStudioClient  # cliente para LM Studio

logger = setup_logger()

# Caminhos dos arquivos de entrada e saída
ARQUIVO_ENTRADA = "./extracted/strings_RADIO.csv"
ARQUIVO_SAIDA = "./translated/strings_RADIO_traduzido_local.csv"

# Prompt otimizado para modelos locais (mais conciso)
PROMPT_BASE = """
Você é um tradutor de jogos com foco em localização fiel ao original. Traduza a frase abaixo do inglês para português brasileiro, mantendo o tom e contexto típico de um jogo de espionagem como Metal Gear Solid. 

REGRAS IMPORTANTES:
- Preserve o estilo e não traduza nomes próprios como "Snake", "Otacon", "Codec", "VR", etc.
- Se a frase for um comando curto, preserve o formato conciso
- Se o texto fornecido não for inglês, devolva o texto original
- Não retorne nada além do texto original ou a tradução, quando for o caso.
- Mantenha o tamanho da tradução próximo ao original para compatibilidade com o jogo
- Tente manter a organização de caracteres como quebras de linhas nas traduções
- Priorize clareza e naturalidade em português brasileiro
- Para diálogos, mantenha o tom característico de cada personagem

Contexto: Metal Gear Solid (PS1) - jogo de espionagem tática com elementos sci-fi
"""

# Configuração do modelo local
# Ajuste conforme seu modelo no LM Studio
LOCAL_MODEL = os.getenv("LMSTUDIO_MODEL", "local-model")
BASE_URL = os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234")


def calcular_tamanho_bytes(texto):
    """Calcula o tamanho em bytes do texto usando codificação UTF-8"""
    return len(str(texto).encode('utf-8'))


def verificar_lmstudio():
    """Verifica se o LM Studio está rodando e acessível"""
    print("\n🔍 Verificando LM Studio...")
    
    client = LMStudioClient(base_url=BASE_URL, modelo=LOCAL_MODEL)
    
    if client.testar_conexao():
        info_modelo = client.obter_info_modelo()
        print(f"✅ Conectado ao LM Studio!")
        print(f"📋 Modelo: {info_modelo.get('nome', 'Desconhecido')}")
        print(f"🔗 URL: {BASE_URL}")
        return client
    else:
        print(f"❌ Não foi possível conectar ao LM Studio em {BASE_URL}")
        print("\n💡 Verifique se:")
        print("   1. LM Studio está rodando")
        print("   2. Um modelo está carregado")
        print("   3. A porta está correta (padrão: 1234)")
        print("   4. A URL no .env está correta")
        return None


def estimar_tempo_total(total_textos, client):
    """Estima tempo total baseado na configuração atual"""
    status = client.obter_status_rate_limit()
    rpm = status['limite_minuto']
    delay = status['delay_entre_requests']
    
    # Tempo baseado no rate limit
    tempo_rate_limit = total_textos / rpm * 60
    
    # Tempo baseado no delay + tempo de processamento estimado
    tempo_processamento_estimado = 2  # 2s por tradução (estimativa)
    tempo_total_estimado = total_textos * (delay + tempo_processamento_estimado)
    
    # Usa o maior dos dois
    tempo_final = max(tempo_rate_limit, tempo_total_estimado)
    
    return tempo_final


def traduzir_csv_local(entrada, saida):
    """
    Traduz CSV usando modelo local via LM Studio.
    
    Parâmetros:
        entrada (str): Arquivo CSV de entrada
        saida (str): Arquivo CSV de saída
    
    Funcionalidades:
        - Usa modelo local (sem custos)
        - Rate limiting otimizado para hardware local
        - Backups automáticos frequentes
        - Estimativas de tempo realistas
        - Recuperação de falhas
    """
    
    # Verifica conexão primeiro
    client = verificar_lmstudio()
    if not client:
        return False
    
    if not os.path.exists(entrada):
        logger.error(f"Arquivo de entrada não encontrado: {entrada}")
        return False

    logger.info(f"Lendo arquivo de entrada: {entrada}")
    df = pd.read_csv(entrada)

    if "texto" not in df.columns:
        logger.error("Coluna 'texto' não encontrada no CSV.")
        return False

    # Prepara colunas
    if "texto_traduzido" not in df.columns:
        df["texto_traduzido"] = ""
    
    if "tamanho_original" not in df.columns:
        df["tamanho_original"] = df["texto"].apply(calcular_tamanho_bytes)
    
    if "tamanho_texto_traduzido" not in df.columns:
        df["tamanho_texto_traduzido"] = 0

    total_linhas = len(df)
    linhas_pendentes = df["texto_traduzido"].isna() | df["texto_traduzido"].str.strip().eq("")
    total_para_traduzir = linhas_pendentes.sum()

    logger.info(f"Total de linhas no CSV: {total_linhas}")
    logger.info(f"Linhas pendentes de tradução: {total_para_traduzir}")
    
    if total_para_traduzir == 0:
        logger.info("✅ Todas as traduções já foram realizadas!")
        return True
    
    # Estimativa de tempo
    tempo_estimado = estimar_tempo_total(total_para_traduzir, client)
    print(f"⏱️  Tempo estimado: {tempo_estimado/60:.1f} minutos ({tempo_estimado/3600:.1f} horas)")
    
    # Confirma se deve continuar para trabalhos longos
    if tempo_estimado > 1800:  # > 30 minutos
        resposta = input(f"\n⚠️  Trabalho longo estimado ({tempo_estimado/3600:.1f}h). Continuar? (s/N): ")
        if resposta.lower() not in ['s', 'sim', 'y', 'yes']:
            print("❌ Cancelado pelo usuário.")
            return False
    
    # Status inicial
    status_inicial = client.obter_status_rate_limit()
    info_modelo = client.obter_info_modelo()
    
    print(f"\n🚀 Iniciando tradução...")
    print(f"📋 Modelo: {info_modelo['nome']}")
    print(f"⚡ Rate limit: {status_inicial['limite_minuto']}/min, delay: {status_inicial['delay_entre_requests']}s")

    # Estatísticas
    traducoes_realizadas = 0
    traducoes_falharam = 0
    soma_diferenca_bytes = 0
    max_diferenca_positiva = 0
    max_diferenca_negativa = 0
    tempo_inicio = time.time()
    
    # Frequência de backup e estatísticas
    backup_interval = 25  # A cada 25 traduções
    stats_interval = 50   # Estatísticas a cada 50

    try:
        for idx, row in tqdm(df.iterrows(), total=total_linhas, desc="Traduzindo"):
            if linhas_pendentes.iloc[idx]:
                texto_original = str(row["texto"])

                if not texto_original.strip():
                    continue

                try:
                    tamanho_original = calcular_tamanho_bytes(texto_original)
                    
                    # Traduz usando modelo local
                    traducao = client.traduzir_texto(
                        texto_original, 
                        contexto=PROMPT_BASE,
                        tamanho_original=tamanho_original,
                        temperatura=0.2,  # Mais determinístico para tradução
                        max_tokens=min(200, tamanho_original * 3)  # Limita baseado no tamanho original
                    )
                    
                    if traducao and traducao.strip():
                        tamanho_traducao = calcular_tamanho_bytes(traducao)
                        diferenca = tamanho_traducao - tamanho_original
                        
                        # Atualiza DataFrame
                        df.at[idx, "texto_traduzido"] = traducao
                        df.at[idx, "tamanho_original"] = tamanho_original
                        df.at[idx, "tamanho_texto_traduzido"] = tamanho_traducao
                        
                        # Atualiza estatísticas
                        traducoes_realizadas += 1
                        soma_diferenca_bytes += diferenca
                        max_diferenca_positiva = max(max_diferenca_positiva, diferenca)
                        max_diferenca_negativa = min(max_diferenca_negativa, diferenca)
                        
                        logger.debug(f"[{idx}] {texto_original[:30]}... -> {traducao[:30]}... ({tamanho_original}b -> {tamanho_traducao}b)")
                    else:
                        logger.warning(f"Tradução vazia para linha {idx}: {texto_original[:50]}")
                        traducoes_falharam += 1
                        
                except Exception as e:
                    logger.error(f"Erro ao traduzir linha {idx}: {e}")
                    traducoes_falharam += 1
                    continue

                # Backup periódico
                if traducoes_realizadas % backup_interval == 0 and traducoes_realizadas > 0:
                    os.makedirs(os.path.dirname(saida), exist_ok=True)
                    df.to_csv(saida, index=False, encoding="utf-8")
                    logger.info(f"💾 Backup automático salvo ({traducoes_realizadas} traduções)")

                # Estatísticas periódicas
                if traducoes_realizadas % stats_interval == 0 and traducoes_realizadas > 0:
                    tempo_decorrido = time.time() - tempo_inicio
                    velocidade = traducoes_realizadas / (tempo_decorrido / 60)
                    tempo_restante = (total_para_traduzir - traducoes_realizadas) / velocidade if velocidade > 0 else 0
                    
                    status = client.obter_status_rate_limit()
                    
                    print(f"\n📊 Progresso: {traducoes_realizadas}/{total_para_traduzir}")
                    print(f"⚡ Velocidade: {velocidade:.1f} trad/min")
                    print(f"⏱️  Tempo restante: ~{tempo_restante:.1f} min")
                    print(f"🔧 Rate limit: {status['requests_ultimo_minuto']}/{status['limite_minuto']} (último minuto)")
                    if traducoes_falharam > 0:
                        print(f"⚠️  Falhas: {traducoes_falharam}")

    except KeyboardInterrupt:
        print(f"\n⚠️  Interrompido pelo usuário após {traducoes_realizadas} traduções")
        # Salva o progresso mesmo se interrompido
        os.makedirs(os.path.dirname(saida), exist_ok=True)
        df.to_csv(saida, index=False, encoding="utf-8")
        logger.info(f"💾 Progresso salvo em: {saida}")
        return False

    # Salva resultado final
    os.makedirs(os.path.dirname(saida), exist_ok=True)
    df.to_csv(saida, index=False, encoding="utf-8")
    
    # Estatísticas finais
    tempo_total = time.time() - tempo_inicio
    
    print(f"\n✅ TRADUÇÃO CONCLUÍDA!")
    print(f"📊 Traduções realizadas: {traducoes_realizadas}")
    print(f"❌ Falhas: {traducoes_falharam}")
    print(f"⏱️  Tempo total: {tempo_total/60:.1f} minutos")
    
    if traducoes_realizadas > 0:
        velocidade_final = traducoes_realizadas / (tempo_total / 60)
        media_diferenca = soma_diferenca_bytes / traducoes_realizadas
        
        print(f"⚡ Velocidade média: {velocidade_final:.1f} traduções/minuto")
        print(f"📏 Diferença média de bytes: {media_diferenca:+.1f}")
        print(f"🔺 Maior aumento: +{max_diferenca_positiva}b")
        print(f"🔻 Maior redução: {max_diferenca_negativa}b")
        
        # Análise final de tamanhos
        df_traduzidas = df[df["texto_traduzido"].str.strip().ne("")]
        if not df_traduzidas.empty:
            crescimento_medio = ((df_traduzidas["tamanho_texto_traduzido"] - df_traduzidas["tamanho_original"]) / df_traduzidas["tamanho_original"] * 100).mean()
            print(f"📈 Crescimento médio: {crescimento_medio:+.1f}%")
    
    print(f"💾 Arquivo salvo: {saida}")
    return True


def analisar_traducoes(arquivo_csv):
    """
    Analisa as traduções realizadas, gerando estatísticas sobre tamanhos e diferenças.
    
    Parâmetros:
        arquivo_csv (str): Caminho para o arquivo CSV com traduções
    """
    if not os.path.exists(arquivo_csv):
        logger.error(f"Arquivo não encontrado: {arquivo_csv}")
        return
    
    df = pd.read_csv(arquivo_csv)
    
    # Filtra apenas linhas com tradução
    df_traduzidas = df[df["texto_traduzido"].astype(str).str.strip().ne("")]
    
    if df_traduzidas.empty:
        logger.info("Nenhuma tradução encontrada para análise.")
        return
    
    total_traducoes = len(df_traduzidas)
    
    # Calcula estatísticas
    tamanho_orig_total = df_traduzidas["tamanho_original"].sum()
    tamanho_trad_total = df_traduzidas["tamanho_texto_traduzido"].sum()
    diferenca_total = tamanho_trad_total - tamanho_orig_total
    
    # Análise por faixas de tamanho
    df_traduzidas["diferenca_bytes"] = df_traduzidas["tamanho_texto_traduzido"] - df_traduzidas["tamanho_original"]
    df_traduzidas["diferenca_percentual"] = (df_traduzidas["diferenca_bytes"] / df_traduzidas["tamanho_original"]) * 100
    
    logger.info(f"\n=== ANÁLISE DE TRADUÇÕES ===")
    logger.info(f"Total de traduções: {total_traducoes}")
    logger.info(f"Bytes originais: {tamanho_orig_total:,}")
    logger.info(f"Bytes traduzidos: {tamanho_trad_total:,}")
    logger.info(f"Diferença total: {diferenca_total:+,} bytes ({diferenca_total/tamanho_orig_total*100:+.1f}%)")
    logger.info(f"\nDiferença média por texto: {df_traduzidas['diferenca_bytes'].mean():+.1f} bytes")
    logger.info(f"Diferença mediana: {df_traduzidas['diferenca_bytes'].median():+.1f} bytes")
    logger.info(f"Crescimento percentual médio: {df_traduzidas['diferenca_percentual'].mean():+.1f}%")
    
    # Textos com maior crescimento/redução
    maior_crescimento = df_traduzidas.loc[df_traduzidas["diferenca_bytes"].idxmax()]
    maior_reducao = df_traduzidas.loc[df_traduzidas["diferenca_bytes"].idxmin()]
    
    logger.info(f"\nMaior crescimento: +{maior_crescimento['diferenca_bytes']}b")
    logger.info(f"  Original: {maior_crescimento['texto'][:60]}...")
    logger.info(f"  Tradução: {maior_crescimento['texto_traduzido'][:60]}...")
    
    logger.info(f"\nMaior redução: {maior_reducao['diferenca_bytes']}b")
    logger.info(f"  Original: {maior_reducao['texto'][:60]}...")
    logger.info(f"  Tradução: {maior_reducao['texto_traduzido'][:60]}...")


def configurar_lmstudio():
    """Utilitário para configurar LM Studio facilmente"""
    print("\n🔧 CONFIGURADOR LM STUDIO")
    print("=" * 40)
    
    print("\n1. 📋 Configuração atual:")
    print(f"   URL Base: {BASE_URL}")
    print(f"   Modelo: {LOCAL_MODEL}")
    
    modo_atual = os.getenv("LMSTUDIO_MODE", "balanced")
    print(f"   Modo: {modo_atual}")
    
    print("\n2. 🧪 Testando conexão...")
    client = verificar_lmstudio()
    
    if client:
        print("\n3. 📊 Informações do modelo:")
        info = client.obter_info_modelo()
        status = client.obter_status_rate_limit()
        
        print(f"   Nome: {info.get('nome', 'N/A')}")
        print(f"   Rate limit: {status['limite_minuto']}/min")
        print(f"   Delay entre requests: {status['delay_entre_requests']}s")
        
        print("\n4. 🔤 Teste de tradução:")
        teste_texto = "Hello, Snake. Can you hear me?"
        try:
            resultado = client.traduzir_texto(teste_texto, temperatura=0.1, max_tokens=50)
            print(f"   Original: {teste_texto}")
            print(f"   Tradução: {resultado}")
            print("   ✅ Teste OK!")
        except Exception as e:
            print(f"   ❌ Erro no teste: {e}")
    
    print("\n💡 Dicas para otimizar:")
    print("   • Para velocidade máxima: LMSTUDIO_MODE=fast")
    print("   • Para preservar hardware: LMSTUDIO_MODE=conservative") 
    print("   • Para configuração customizada: LMSTUDIO_MODE=custom")


def menu_principal():
    """Menu principal do tradutor local"""
    while True:
        print("\n" + "="*50)
        print("🏠 TRADUTOR LOCAL - LM STUDIO")
        print("="*50)
        print()
        print("1. 🚀 Iniciar tradução")
        print("2. 🔧 Configurar/testar LM Studio")  
        print("3. 📊 Analisar traduções existentes")
        print("4. ⚙️  Configurar modo de velocidade")
        print("5. 📋 Ver configuração atual")
        print("6. 🚪 Sair")
        print()
        
        try:
            escolha = input("Escolha uma opção (1-6): ").strip()
            
            if escolha == "1":
                print("\n🚀 Iniciando tradução...")
                sucesso = traduzir_csv_local(ARQUIVO_ENTRADA, ARQUIVO_SAIDA)
                if sucesso:
                    print("✅ Tradução concluída com sucesso!")
                else:
                    print("❌ Tradução foi interrompida ou falhou.")
            
            elif escolha == "2":
                configurar_lmstudio()
            
            elif escolha == "3":
                if os.path.exists(ARQUIVO_SAIDA):
                    analisar_traducoes(ARQUIVO_SAIDA)
                else:
                    print(f"❌ Arquivo de traduções não encontrado: {ARQUIVO_SAIDA}")
            
            elif escolha == "4":
                configurar_modo_velocidade()
            
            elif escolha == "5":
                mostrar_configuracao_atual()
            
            elif escolha == "6":
                print("\n👋 Até logo!")
                break
            
            else:
                print("❌ Opção inválida. Escolha entre 1-6.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Até logo!")
            break
        except Exception as e:
            print(f"❌ Erro: {e}")


def configurar_modo_velocidade():
    """Configura o modo de velocidade do LM Studio"""
    print("\n⚡ CONFIGURAÇÃO DE VELOCIDADE")
    print("=" * 35)
    
    modos = {
        "1": ("fast", "Máxima velocidade - 120/min, 0.2s delay"),
        "2": ("balanced", "Equilibrado - 60/min, 0.5s delay"), 
        "3": ("conservative", "Conservador - 30/min, 1.0s delay"),
        "4": ("custom", "Personalizado - você define")
    }
    
    print("\nModos disponíveis:")
    for key, (nome, desc) in modos.items():
        print(f"  {key}. {nome.upper()}: {desc}")
    
    try:
        escolha = input("\nEscolha um modo (1-4): ").strip()
        
        if escolha in modos:
            modo, desc = modos[escolha]
            
            if modo == "custom":
                print("\n🎛️  Configuração personalizada:")
                rpm = int(input("Requests por minuto (ex: 60): "))
                delay = float(input("Delay entre requests em segundos (ex: 0.5): "))
                
                # Atualiza .env
                atualizar_env({
                    "LMSTUDIO_MODE": "custom",
                    "LMSTUDIO_RPM": str(rpm),
                    "LMSTUDIO_DELAY": str(delay)
                })
                
                print(f"✅ Modo customizado configurado: {rpm}/min, {delay}s delay")
            else:
                # Atualiza .env
                atualizar_env({"LMSTUDIO_MODE": modo})
                print(f"✅ Modo configurado: {modo.upper()}")
                print(f"📝 {desc}")
        else:
            print("❌ Opção inválida.")
            
    except ValueError:
        print("❌ Valor inválido inserido.")
    except KeyboardInterrupt:
        print("\n❌ Configuração cancelada.")


def mostrar_configuracao_atual():
    """Mostra a configuração atual completa"""
    print("\n📋 CONFIGURAÇÃO ATUAL")
    print("=" * 25)
    
    print(f"🔗 URL Base: {BASE_URL}")
    print(f"🤖 Modelo: {LOCAL_MODEL}")
    
    modo = os.getenv("LMSTUDIO_MODE", "balanced")
    print(f"⚡ Modo: {modo}")
    
    if modo == "custom":
        rpm = os.getenv("LMSTUDIO_RPM", "60")
        delay = os.getenv("LMSTUDIO_DELAY", "0.5")
        print(f"📊 Custom: {rpm}/min, {delay}s delay")
    
    # Testa conexão
    print(f"\n🔍 Status da conexão:")
    client = LMStudioClient(base_url=BASE_URL, modelo=LOCAL_MODEL)
    if client.testar_conexao():
        print("  ✅ Conectado")
        info = client.obter_info_modelo()
        print(f"  📋 Modelo ativo: {info.get('nome', 'N/A')}")
    else:
        print("  ❌ Desconectado")
        print("  💡 Verifique se o LM Studio está rodando")


def atualizar_env(updates):
    """Atualiza variáveis no arquivo .env"""
    env_path = ".env" 
    linhas = []
    
    # Lê arquivo existente
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            linhas = f.readlines()
    
    # Remove linhas que serão atualizadas
    linhas_filtradas = []
    for linha in linhas:
        if not any(linha.startswith(f"{key}=") for key in updates.keys()):
            linhas_filtradas.append(linha)
    
    # Adiciona novas configurações
    for key, value in updates.items():
        linhas_filtradas.append(f"{key}={value}\n")
    
    # Salva arquivo
    with open(env_path, 'w', encoding='utf-8') as f:
        f.writelines(linhas_filtradas)


if __name__ == "__main__":
    print("🏠 Tradutor Local com LM Studio")
    print("Tradução sem custos usando modelos locais!")
    
    # Verifica se há traduções pendentes
    if os.path.exists(ARQUIVO_ENTRADA):
        df_check = pd.read_csv(ARQUIVO_ENTRADA)
        if "texto_traduzido" in df_check.columns:
            pendentes = (df_check["texto_traduzido"].isna() | df_check["texto_traduzido"].str.strip().eq("")).sum()
            if pendentes > 0:
                print(f"📊 {pendentes} traduções pendentes encontradas")
        else:
            print(f"📊 {len(df_check)} textos para traduzir")
    
    # Executa menu ou tradução direta
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--auto":
        # Modo automático para scripts
        print("🤖 Modo automático ativado")
        traduzir_csv_local(ARQUIVO_ENTRADA, ARQUIVO_SAIDA)
    else:
        # Modo interativo
        menu_principal()