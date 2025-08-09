# Projeto de Tradução - Metal Gear Solid (PS1)

Este projeto tem como objetivo traduzir o jogo **Metal Gear Solid (PS1)** para o português brasileiro, respeitando a estrutura técnica da ROM original e buscando manter a fidelidade ao tom e estilo do jogo.

> **Nota:** Este é um projeto experimental de aprendizado. Não tenho experiência prévia com ROM hacking e estou aprendendo ao longo do processo, através de tentativa e erro, estudo de ferramentas da comunidade e engenharia reversa dos arquivos do jogo.

## Estado Atual do Projeto (06/08/2025)

- Foi possível extrair e mapear com precisão os textos armazenados em arquivos `.DAT` (como `RADIO.DAT`) do disco 1.
- Desenvolvido um pipeline de scripts que:
  - Extrai textos binários (`scan_texts.py`);
  - Reinsere os textos traduzidos respeitando o limite de bytes do original, indicando traduções que possam quebrar os ponteiros do jogo, assim como usando linhas originais em caso de problemas (`rebuild_text.py`);
- Os arquivos modificados são salvos como `.DAT` novos (`*_PATCHED.DAT`), prontos para serem reimportados para a ISO do jogo.
- Estrutura organizada por pastas, com README individual em cada diretório técnico.
- Scripts prontos para serem automatizados em pipeline de tradução em massa.

### Desafios Atuais

- **Acentuação**: Embora o jogo use encoding `Shift_JIS`, os caracteres acentuados do português não são reconhecidos nativamente pelo jogo.


- **Textos maiores que o original**: O jogo tem espaço visual para textos maiores no Codec, mas os arquivos `.DAT` usam alocação fixa por ponteiro. Ainda não sei:
  - Como localizar e editar os ponteiros;
  - Se o engine do jogo aceita realocação de texto;
  - Ou se é preciso manter o tamanho byte-a-byte.

-> Decidi ajustar a tradução nesses cenários para que ela ocupe no maximo o mesmo espaço do texto original em inglês, portanto, a tradução fará uso de algumas contrações, como o: voce -> vc, tambem -> tbm, Coronel -> Cel, entre outros ajustes que facilitem a adequação do tamanho da tradução.

-  **Testes in-game**: Foram feitos testes com o arquivo `RADIO.DAT` reimportado. Foram reinseridos todos os textos de forma a não violar a estrutura do jogo evitando crashes.

---

## Estrutura do Projeto

```plaintext
├── tools/              # Scripts para extração, tradução e reempacotamento de arquivos
├── assets/             # Arquivos extraídos dos discos do jogo (ex: RADIO.DAT)
├── translated/         # CSVs com textos traduzidos e prontos para reempacotamento
├── extracted/          # Arquivos CSV com textos extraídos dos binários
├── duckstation/        # Configurações e save states para testes rápidos
├── programs/           # Softwares utilizados no processo (alguns precisam ser baixados)
├── .env                # Arquivo com chaves de API e links de ferramentas (opcional)
```

---

## Ferramentas e Utilitários

O projeto faz uso de diversas ferramentas da comunidade:

| Ferramenta         | Descrição                                  | Variável de Ambiente Sugerida |
| ------------------ | ------------------------------------------ | ----------------------------- |
| **CDMage**         | Editor de ISOs do PS1                      | `CDMAGE_URL`                  |
| **DuckStation**    | Emulador moderno com suporte a save states | `DUCKSTATION_URL`             |

O caminho dos programas pode ser configurado via `.env` ou variáveis de ambiente para facilitar automações.

---

## Como Executar

### 1. Extração de textos

```bash
python tools/scan_texts.py
```


### 2. Analisar traduções maiores que o texto original

```bash
python tools/overflow_checker.py
```

### 3. Reempacotar binário com os textos traduzidos

```bash
python tools/rebuild_text.py
```

### 4. Comparar offsets Originais e Patechados

```bash
python tools/offset_analyzer.py
```

---

## Contribuições Futuras

* Desenvolver ou adaptar ferramentas de localização de ponteiros;
* Criar um patch `.xdelta` ou `.ppf` para aplicar a tradução na ISO original;
* Traduzir menus, videos, legendas e assets gráficos.

---

## Contato

Caso tenha interesse em ajudar ou queira sugerir melhorias, sinta-se livre para abrir uma issue ou contribuir com pull requests!

---

*Projeto criado com fins educacionais e sem fins lucrativos. Todos os direitos sobre o jogo Metal Gear Solid pertencem à Konami.*