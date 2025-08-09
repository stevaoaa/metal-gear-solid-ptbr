# Ferramentas de Extração e Inserção de Texto

Scripts utilizados para:
- Extrair textos dos arquivos `.DAT`
- Recriar arquivos `.DAT` com traduções
- Analisar overflows
- Comparar patches com arquivos originais

## Scripts

- `scan_texts.py`: Extrai textos legíveis com encoding Shift-JIS de arquivos binários.
- `rebuild_text.py`: Substitui os textos no arquivo original `.DAT` com traduções (com padding e validação de tamanho).
- `overflow_checker.py`: Script para analisar overflows em traduções. Calcula tamanhos em bytes, identifica overflows e destaca células problemáticas
- `offset_analyzer.py`: Inspetor de Offsets - Análise detalhada do arquivo após patch
Verifica exatamente o que está nos offsets especificados.

## Requisitos
- Python 3.9+
- `.env` com:
  ```env

    ````

## Executando

```bash
python tools/scan_texts.py
python tools/rebuild_text.py
python tools/overflow_checker.py
python tools/offset_analyzer.py
```
