# Ferramentas de Extração e Inserção de Texto

Scripts utilizados para:
- Extrair textos dos arquivos `.DAT`
- Traduzir textos usando LLMs
- Recriar arquivos `.DAT` com traduções
- Fazer padding ou fallback de traduções

## Scripts

- `scan_texts.py`: Extrai textos legíveis com encoding Shift-JIS de arquivos binários.
- `translate_texts.py`: Usa um modelo de LLM para traduzir os textos extraídos.
- `rebuild_dat.py`: Substitui os textos no arquivo original `.DAT` com traduções (com padding e validação de tamanho).

## Requisitos
- Python 3.9+
- `.env` com:
  ```env

    ````

## Executando

```bash
python tools/scan_texts.py
python tools/translate_texts.py
python tools/pad_missing_translations.py
python tools/rebuild_dat.py
```
