# Ferramentas de Extração e Inserção de Texto

Scripts utilizados para extrair, analisar e reinserir textos nos arquivos `.DAT` do Metal Gear Solid PS1.

> Todos os scripts são executados pelo `main.py` na raiz do projeto. É possível rodá-los diretamente também, mas o uso via `main.py` é o recomendado pois garante que os caminhos e configurações do `config.py` sejam aplicados corretamente.

---

## Scripts

### `scan_texts.py`
Extrai textos legíveis com encoding Shift-JIS de arquivos binários. Suporta mesclagem com traduções existentes para preservar trabalho anterior.

- **Requer:** arquivo binário original em `assets/fontes/<CD>/` (ex: `VOX.DAT`)
- **Gera:** CSV em `extracted/<CD>/strings_<ARQUIVO>.csv`
- Se já existir um CSV traduzido em `translated/<CD>/strings_<ARQUIVO>_traduzido.csv`, mescla automaticamente as traduções existentes na coluna `texto_traduzido`

---

### `rebuild_text.py`
Substitui os textos no arquivo original `.DAT` com as traduções (com padding e validação de tamanho). Detecta automaticamente a estratégia por tipo de arquivo (`STAGE.DIR` usa estratégia avançada, demais usam estratégia genérica).

- **Requer:**
  - Arquivo binário original em `assets/fontes/<CD>/`
  - CSV traduzido em `translated/<CD>/strings_<ARQUIVO>_traduzido.csv` com a coluna `texto_traduzido` preenchida
- **Gera:** arquivo binário patcheado em `patches/<CD>/` (ex: `VOX_PATCHED.DAT`) e relatório de inserção em `output/<CD>/`

---

### `overflow_checker.py`
Analisa overflows nas traduções. Calcula tamanhos em bytes, identifica strings maiores que o original e gera relatório Excel com células destacadas por severidade (vermelho = crítico >5 bytes, amarelo = moderado 1–5 bytes).

- **Requer:** CSV traduzido em `translated/<CD>/strings_<ARQUIVO>_traduzido.csv` com as colunas `texto` e `texto_traduzido`
- **Gera:** relatório `.xlsx` em `output/<CD>/overflow_<ARQUIVO>.xlsx` (com `--excel`)

---

### `offset_analyzer.py`
Inspetor de offsets — analisa em detalhe o que está em posições específicas do arquivo, comparando original e patcheado.

- **Requer:** arquivo binário original em `assets/fontes/<CD>/`
- Com a flag `--patched`: **requer** também o arquivo patcheado em `patches/<CD>/`
- Opcionalmente usa o CSV em `translated/<CD>/` para cruzar offset com tradução

---

### `offset_finder.py`
Busca a posição (offset) de um texto específico dentro do arquivo binário. Útil para confirmar se uma string foi inserida corretamente após o patch.

- **Requer:** arquivo binário original em `assets/fontes/<CD>/`
- Opcionalmente usa o CSV em `extracted/<CD>/` ou `translated/<CD>/` para enriquecer os resultados

---

### `extracted_filter.py`
Filtra um CSV de textos extraídos mantendo apenas as linhas que correspondem a uma lista de offsets de interesse.

- **Requer:**
  - Arquivo `.txt` com um offset por linha (ex: `extracted/target_offsets_cd1.txt`)
  - CSV extraído em `extracted/<CD>/strings_<ARQUIVO>.csv` (gerado pelo `scan_texts.py`)
- **Gera:** novo CSV filtrado no mesmo diretório do CSV de entrada

---

## Configuração

Os caminhos de todos os arquivos são gerenciados pelo `config.py` na raiz. Para alterar onde os CDs estão armazenados, edite o `.env` na raiz:

```env
CD1_PATH=./assets/fontes/CD1
CD2_PATH=./assets/fontes/CD2
```

---

## Executando via main.py (recomendado)

```bash
# Ver arquivos disponíveis
python main.py info --cd CD1

# Extrair textos
python main.py extract --cd CD1 --vox
python main.py extract --cd CD1 --all

# Verificar overflows
python main.py check --cd CD1 --stage
python main.py check --cd CD1 --all --excel

# Reempacotar com traduções
python main.py rebuild --cd CD1 --radio

# Inspecionar offsets
python main.py analyze --cd CD1 vox 0x1fc 0x24c

# Buscar texto no binário
python main.py find --cd CD1 vox "Snake"

# Filtrar CSV por lista de offsets
python main.py filter offsets.txt extracted/CD1/strings_VOX.csv

# Pipeline completo
python main.py pipeline --cd CD1 --all
```

## Executando diretamente

```bash
python tools/scan_texts.py --cd CD1 --vox
python tools/rebuild_text.py --cd CD1 --stage
python tools/overflow_checker.py --cd CD1 --vox
python tools/offset_analyzer.py --cd CD1 --vox
python tools/offset_finder.py --cd CD1 --vox --text "Snake"
python tools/extracted_filter.py offsets.txt strings_VOX.csv
```