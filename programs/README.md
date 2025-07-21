# Programas Recomendados para Edição de Imagem de Disco

Alguns programas são úceis para extrair/inserir os arquivos `.DAT` modificados de volta na imagem `.bin` do jogo.

## Ferramentas

### CDmage
- Manipulação de arquivos em imagens `.bin/.cue`
- [CDmage B5 Download](https://cdmage.sourceforge.net/) (ou defina via env)
```env
CDMAGE_URL=https://cdmage.sourceforge.net/files/CDmage1-02-1B5.zip
```

---

Essas ferramentas são opcionais, mas altamente recomendadas para reconstruir a ISO e testar emuladores ou hardware real.


# DuckStation - Emulador para Testes

Utilizamos o DuckStation para testar a ISO modificada do Metal Gear Solid.

## Instalação

Você pode baixar a versão mais recente do DuckStation em:
- [https://github.com/stenzek/duckstation/releases](https://github.com/stenzek/duckstation/releases)

Ou defina a variável de ambiente para apontar para o link desejado:
```env
DUCKSTATION_URL=https://github.com/stenzek/duckstation/releases/latest/download/duckstation-windows-x64.zip
```

## Recomendações

* Usar as versões standalone (sem instalador).
* Configurar a BIOS do PlayStation na interface do DuckStation.
* Apontar para a imagem `.cue` ou `.bin` gerada a partir dos arquivos modificados.