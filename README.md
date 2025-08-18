# Projeto de Tradução - Metal Gear Solid (PS1)

Este projeto tem como objetivo traduzir o jogo **Metal Gear Solid (PS1)** para o português brasileiro, respeitando a estrutura técnica da ROM original e buscando manter a fidelidade ao tom e estilo do jogo.

> **Nota:** Este é um projeto experimental de aprendizado. Não tenho experiência prévia com ROM hacking e estou aprendendo ao longo do processo, através de tentativa e erro, estudo de ferramentas da comunidade e engenharia reversa dos arquivos do jogo.

## Estado Atual do Projeto (17/08/2025)

- Foram extraidos os textos armazenados nos arquivos: `RADIO.DAT`, `DEMO.DAT`, `STAGE.DIR`, `VOX.DAT`, `ZMOVIE.STR`  do disco 1.

- Todos os textos foram inicialmente traduzidos

- Foi corrigido um calculo errado de caracteres de controle e padding. Após isso, foi necessário realizar a revisão das traduções de todos os arquivos.

- A revisão foi concluida nos arquivos: `RADIO.DAT`, `STAGE.DIR`, `ZMOVIE.STR`

- Ainda é necessário realizar os ajustes no arquivo `DEMO.DAT` e finalizar a adaptação da tradução para o arquivo `VOX.DAT`.


### Desafios Atuais

- **Acentuação**: Embora o jogo use encoding `Shift_JIS`, os caracteres acentuados do português não são reconhecidos nativamente pelo jogo.
  - Decidi remover todas as acentuações e `ç` de palavras em pt-br
  - Acento agudo do `é` foram substituidos pela expressão `eh`


- **Textos maiores que o original**: O jogo tem espaço visual para textos maiores no Codec, mas os arquivos `.DAT` usam alocação fixa por ponteiro.
  - Decidi adaptar os textos em pt-br para atender o tamanho da string original;
  - Decidi ajustar a tradução nesses cenários para que ela ocupe no maximo o mesmo espaço do texto original em inglês, portanto, a tradução fará uso de algumas contrações, como o: voce -> vc, tambem -> tbm, Coronel -> Cel, entre outros ajustes que facilitem a adequação do tamanho da tradução.

-  **Testes in-game**: Atualmente estão sendo feitos testes com todos os arquivos reimportados para verificar a quantidade de texto que ainda é necessária ser traduzida no CD1. 

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