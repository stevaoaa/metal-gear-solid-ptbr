# Projeto de Tradução - Metal Gear Solid (PS1)

Este projeto tem como objetivo traduzir o jogo **Metal Gear Solid (PS1)** para o português brasileiro, respeitando a estrutura técnica da ROM original e buscando manter a fidelidade ao tom e estilo do jogo.

> **Nota:** Este é um projeto experimental de aprendizado. Não tenho experiência prévia com ROM hacking e estou aprendendo ao longo do processo, através de tentativa e erro, estudo de ferramentas da comunidade e engenharia reversa dos arquivos do jogo.

## Estado Atual do Projeto (05/04/2026)

- Todos os textos do CD1 foram extraídos, traduzidos e reinseridos com sucesso nos arquivos: `RADIO.DAT`, `DEMO.DAT`, `STAGE.DIR`, `VOX.DAT`, `ZMOVIE.STR`

- O processo de reinserção foi validado sem problemas de overflow — todas as traduções respeitam o tamanho original das strings.

- **Próximo passo:** testes in-game no CD1 para validar a tradução em contexto real.

- CD2 ainda não iniciado: A princípio, o CD2 utiliza os mesmos endereços de memória para armazenamento de strings que o CD1. Tecnicamente, isso significa que bastaria aplicar a reinserção das traduções do CD1 diretamente no CD2, sem necessidade de nova extração ou processo de tradução. Porém, essa hipótese ainda não foi validada in-game.


### Desafios Atuais

- **Acentuação**: Embora o jogo use encoding `Shift_JIS`, os caracteres acentuados do português não são reconhecidos nativamente pelo jogo.
  - Decidi remover todas as acentuações e `ç` de palavras em pt-br
  - Acento agudo do `é` foi substituído pela expressão `eh`

- **Textos maiores que o original**: O jogo tem espaço visual para textos maiores no Codec, mas os arquivos `.DAT` usam alocação fixa por ponteiro.
  - Decidi adaptar os textos em pt-br para atender o tamanho da string original
  - A tradução fará uso de algumas contrações: `voce → vc`, `tambem → tbm`, `Coronel → Cel`, entre outros ajustes

- **Testes in-game**: Atualmente estão sendo feitos testes com todos os arquivos reimportados para verificar a quantidade de texto que ainda é necessária ser traduzida no CD1.

---

## Estrutura do Projeto

```plaintext
├── main.py             # Ponto de entrada unificado — executa todos os scripts via subcomandos
├── config.py           # Configuração centralizada: caminhos, mapeamento de arquivos, estratégias
├── .env                # Caminhos dos CDs (opcional, ver .env.example)
├── tools/              # Scripts de extração, análise e reempacotamento
├── assets/             # Arquivos originais extraídos dos discos (RADIO.DAT, VOX.DAT, etc.)
├── extracted/          # CSVs com textos extraídos dos binários (por CD: extracted/CD1/)
├── translated/         # CSVs com textos traduzidos prontos para reempacotamento (por CD)
├── patches/            # Arquivos binários patcheados gerados pelo rebuild (por CD)
├── output/             # Relatórios de overflow e análise de inserção (por CD)
├── duckstation/        # Emulador e configurações para testes rápidos
├── programs/           # Softwares auxiliares utilizados no processo
└── screenshots/        # Capturas de tela dos testes in-game
```

---

## Requisitos

- Python 3.9+
- Dependências: `pip install -r requirements.txt`
- Arquivo `.env` na raiz (copie o `.env.example` e ajuste os caminhos se necessário)

---

## Como Executar

Todos os scripts são orquestrados pelo `main.py`. Use `python main.py --help` para ver todos os comandos disponíveis.

### Listar arquivos disponíveis por CD

```bash
python main.py info --cd CD1
python main.py info --cd CD2
```

### 1. Extração de textos

```bash
python main.py extract --cd CD1 --vox
python main.py extract --cd CD1 --all       # todos os arquivos padrão
```

### 2. Verificar overflows nas traduções

```bash
python main.py check --cd CD1 --vox
python main.py check --cd CD1 --all --excel  # gera relatório Excel
```

### 3. Reempacotar binário com textos traduzidos

```bash
python main.py rebuild --cd CD1 --vox
python main.py rebuild --cd CD1 --stage
```

### 4. Inspecionar offsets após patch

```bash
python main.py analyze --cd CD1 vox 0x1fc 0x24c
python main.py analyze --cd CD1 --patched vox 0x1fc   # analisa o arquivo patcheado
```

### 5. Pipeline completo (extract → check → rebuild)

```bash
python main.py pipeline --cd CD1 --vox
python main.py pipeline --cd CD1 --all --skip-check
```

---

## Screenshots

### Cutscenes
![Cutscene 1](screenshots/Metal%20Gear%20Solid%20(USA)%20(Disc%201)%202025-08-18-00-15-24.png)

### Briefing
![Briefing](screenshots/Metal%20Gear%20Solid%20(USA)%20(Disc%201)%202025-08-18-00-17-01.png)

### Especial
![Especial](screenshots/Metal%20Gear%20Solid%20(USA)%20(Disc%201)%202025-08-18-00-17-47.png)

### Codec
![Codec](screenshots/Metal%20Gear%20Solid%20(USA)%20(Disc%201)%202025-08-18-00-19-59.png)

---

## Contribuições Futuras

- Desenvolver ou adaptar ferramentas de localização de ponteiros
- Criar um patch `.xdelta` ou `.ppf` para aplicar a tradução na ISO original
- Traduzir menus, vídeos, legendas e assets gráficos

---

## Contato

Caso tenha interesse em ajudar ou queira sugerir melhorias, sinta-se livre para abrir uma issue ou contribuir com pull requests!

---

*Projeto criado com fins educacionais e sem fins lucrativos. Todos os direitos sobre o jogo Metal Gear Solid pertencem à Konami.*