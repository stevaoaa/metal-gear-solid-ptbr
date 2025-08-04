# Guia de Setup - LM Studio para Tradução Local

Este guia ajuda a configurar o processo de tradução usando modelos locais via LM Studio.

## Pré-requisitos

### Hardware Recomendado
- **RAM**: Mínimo 8GB, recomendado 16GB+ 
- **GPU**: NVIDIA com 6GB+ VRAM (opcional, mas acelera muito)
- **CPU**: Processador moderno (Intel i5/AMD Ryzen 5+)
- **Armazenamento**: 10-50GB livres (dependendo do modelo)

### Software Necessário  
- **LM Studio**: [lmstudio.ai](https://lmstudio.ai) (gratuito)
- **Python 3.9+** com as dependências do projeto

## Passo a Passo

### 1. Instalar o LM Studio
1. Baixe em [lmstudio.ai](https://lmstudio.ai)
2. Instale normalmente (Windows/Mac/Linux)
3. Abra o LM Studio

### 2. Baixar um Modelo de Tradução
Recomendações por categoria:

#### **Melhor Qualidade** (se tiver hardware potente)
```
microsoft/Phi-3-medium-4k-instruct-gguf
- Tamanho: ~8GB
- RAM necessária: 12GB+
- Excelente para tradução
```

#### **Equilibrado** (recomendado para maioria)
```
microsoft/Phi-3-mini-4k-instruct-gguf
- Tamanho: ~2.5GB  
- RAM necessária: 6GB
- Boa qualidade, velocidade razoável
```

#### **Mais Rápido** (hardware limitado)
```
microsoft/Phi-3-mini-4k-instruct-q4_k_m.gguf
- Tamanho: ~1.5GB
- RAM necessária: 4GB
- Mais rápido, qualidade boa
```

#### **Alternativas Recomendadas**
```
Meta-Llama-3.1-8B-Instruct-gguf (se tiver 16GB+ RAM)
Mistral-7B-Instruct-v0.3-gguf (muito boa para tradução)
```

### 3. Carregar o Modelo no LM Studio
1. Na aba **"Chat"**, clique em **"Select a model"**
2. Escolha o modelo baixado
3. Ajuste configurações se necessário:
   - **Context Length**: 4096 (suficiente)
   - **GPU Layers**: Máximo possível se tiver GPU
4. Clique **"Load Model"**
5. Aguarde carregar (pode demorar alguns minutos)

### 4. Iniciar o Servidor Local
1. Vá para aba **"Local Server"**
2. Configure a porta (padrão: 1234)
3. Clique **"Start Server"**
4. Verifique se aparece: `Server running on http://localhost:1234`

### 5. Testar a Conexão
```bash
# Teste simples via curl
curl -X POST http://localhost:1234/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "local-model",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 10
  }'
```

### 6. Configurar o Projeto
Edite o arquivo `.env`:
```bash
# Configuração LM Studio
LMSTUDIO_BASE_URL=http://localhost:1234
LMSTUDIO_MODEL=local-model
LMSTUDIO_MODE=balanced
```

## Modos de Configuração

### Fast Mode
```bash
LMSTUDIO_MODE=fast
```
- 120 traduções/minuto
- Delay: 0.2s entre requests
- Use se tiver hardware potente

### Balanced Mode (Padrão)  
```bash
LMSTUDIO_MODE=balanced
```
- 60 traduções/minuto
- Delay: 0.5s entre requests  
- Melhor para maioria dos casos

### Conservative Mode
```bash
LMSTUDIO_MODE=conservative  
```
- 30 traduções/minuto
- Delay: 1s entre requests
- Use se o hardware estiver sobrecarregando

### Custom Mode
```bash
LMSTUDIO_MODE=custom
LMSTUDIO_RPM=45
LMSTUDIO_DELAY=0.8
```

## Otimizações

### Para Velocidade Máxima
1. **Use GPU**: Coloque máximo de layers na GPU
2. **Modelo menor**: Phi-3-mini é mais rápido que modelos maiores
3. **RAM suficiente**: Evite usar swap/virtual memory
4. **Feche outros programas**: Libere recursos

### Para Melhor Qualidade
1. **Modelo maior**: Phi-3-medium ou Llama-3.1-8B
2. **Temperatura baixa**: 0.1-0.3 para tradução
3. **Context length adequado**: 4096 é suficiente
4. **Prompt bem estruturado**: O código já faz isso

### Para Economizar Recursos
1. **Modelo quantizado**: Versões Q4 ou Q8  
2. **Menos layers na GPU**: Se RAM da GPU é limitada
3. **Mode conservative**: Delay maior entre requests

## Troubleshooting

### Erro "Connection refused"
- Verifique se LM Studio está rodando
- Confirme que servidor local está ativo
- Verifique a porta (padrão 1234)

### Modelo muito lento
- Use mais GPU layers
- Escolha modelo menor (Phi-3-mini)
- Aumente LMSTUDIO_DELAY
- Feche outros programas

### Ficando sem memória
- Escolha modelo menor
- Reduza GPU layers
- Use modo conservative
- Reinicie o LM Studio

### Traduções ruins
- Teste modelos diferentes
- Ajuste temperatura (0.1-0.3)
- Verifique se o modelo suporta português
- Use prompt mais específico

## Dicas Extras

### Modelos Recomendados por Uso

**Para Metal Gear Solid especificamente:**
- Phi-3-mini/medium (muito bom com contexto de jogos)
- Mistral-7B (excelente para tradução PT-BR)

**Para tradução geral:**
- Llama-3.1-8B (versátil, alta qualidade)
- Qwen2-7B (muito bom para línguas não-inglesas)

### Estimativas de Tempo
```
Modelo Phi-3-mini + GTX 1660:
- 1000 textos: ~45 minutos
- 5000 textos: ~3.5 horas

Modelo Phi-3-medium + RTX 3070:  
- 1000 textos: ~25 minutos
- 5000 textos: ~2 horas

Só CPU (sem GPU):
- Adicione 2-3x mais tempo
```

### Backup e Recuperação
- O sistema salva backup a cada 25 traduções
- Pode ser interrompido e retomado
- Não perde progresso em falhas
- Ctrl+C interrompe graciosamente