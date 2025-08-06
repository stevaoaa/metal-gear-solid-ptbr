#!/usr/bin/env python3
"""
Script para analisar overflows em traduções.
Calcula tamanhos em bytes, identifica overflows e destaca células problemáticas.
"""

import pandas as pd
import numpy as np
import os
import sys
from datetime import datetime

# Adiciona o diretório pai ao sys.path para permitir importações relativas
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.logger_config import setup_logger


# Inicializa o logger personalizado
logger = setup_logger()

def calcular_tamanho_bytes(texto):
    """Calcula o tamanho em bytes usando codificação latin-1"""
    if pd.isna(texto) or texto == '':
        return 0
    return len(str(texto).encode('latin-1', errors='replace'))

def analisar_overflows(arquivo_csv, arquivo_saida=None):
    """
    Analisa overflows em arquivo CSV de traduções.
    
    Args:
        arquivo_csv (str): Caminho para o arquivo CSV
        arquivo_saida (str): Caminho para arquivo de saída (opcional)
    
    Returns:
        tuple: (DataFrame processado, estatísticas de overflow)
    """
    
    logger.info(f" ANALISADOR DE OVERFLOWS")
    logger.info(f" Arquivo: {arquivo_csv}")
    logger.info("=" * 50)
    
    # Verifica se arquivo existe
    if not os.path.exists(arquivo_csv):
        logger.error(f" Arquivo não encontrado: {arquivo_csv}")
        return None, None
    
    # Carrega dados
    try:
        df = pd.read_csv(arquivo_csv, delimiter='\t')
        logger.info(f" Arquivo carregado: {len(df)} linhas")
    except Exception as e:
        logger.error(f" Erro ao carregar arquivo: {e}")
        return None, None
    
    # Verifica colunas necessárias
    colunas_necessarias = ['texto_traduzido']
    colunas_faltando = [col for col in colunas_necessarias if col not in df.columns]
    
    if colunas_faltando:
        logger.warning(f" Colunas obrigatórias não encontradas: {colunas_faltando}")
        return None, None
    
    # Calcula tamanho em bytes da tradução
    logger.info(" Calculando tamanhos em bytes...")
    df['tamanho_bytes_traducao'] = df['texto_traduzido'].apply(calcular_tamanho_bytes)
    
    # Verifica se existe coluna de referência (tamanho original ou disponível)
    coluna_referencia = None
    if 'tamanho_bytes' in df.columns:
        coluna_referencia = 'tamanho_bytes'
        logger.info(" Usando coluna 'tamanho_bytes' como referência")
    elif 'bytes_disponiveis' in df.columns:
        coluna_referencia = 'bytes_disponiveis'
        logger.info(" Usando coluna 'bytes_disponiveis' como referência")
    elif 'tamanho_original' in df.columns:
        coluna_referencia = 'tamanho_original'
        logger.info(" Usando coluna 'tamanho_original' como referência")
    elif 'texto' in df.columns:
        logger.info(" Calculando tamanho do texto original como referência...")
        df['tamanho_bytes_original'] = df['texto'].apply(calcular_tamanho_bytes)
        coluna_referencia = 'tamanho_bytes_original'
    else:
        logger.info(" Nenhuma coluna de referência encontrada. Usando análise sem comparação.")
    
    # Identifica overflows
    if coluna_referencia:
        logger.info(f" Identificando overflows comparando com '{coluna_referencia}'...")
        
        # Calcula diferenças
        df['diferenca_bytes'] = df['tamanho_bytes_traducao'] - df[coluna_referencia]
        df['tem_overflow'] = df['diferenca_bytes'] > 0
        df['percentual_diferenca'] = ((df['diferenca_bytes'] / df[coluna_referencia]) * 100).round(1)
        
        # Substitui inf por 0 quando referência é 0
        df['percentual_diferenca'] = df['percentual_diferenca'].replace([np.inf, -np.inf], 0)
        
        # Filtra apenas linhas com tradução
        df_com_traducao = df[df['texto_traduzido'].notna() & (df['texto_traduzido'] != '')]
        
        # Estatísticas
        total_traducoes = len(df_com_traducao)
        overflows = df_com_traducao['tem_overflow'].sum()
        
        if total_traducoes > 0:
            taxa_overflow = (overflows / total_traducoes) * 100
            
            logger.info(f"\n ESTATÍSTICAS DE OVERFLOW:")
            logger.info(f"   Total de traduções: {total_traducoes}")
            logger.info(f"   Overflows detectados: {overflows}")
            logger.info(f"   Taxa de overflow: {taxa_overflow:.1f}%")
            
            if overflows > 0:
                maior_overflow = df_com_traducao['diferenca_bytes'].max()
                media_overflow = df_com_traducao[df_com_traducao['tem_overflow']]['diferenca_bytes'].mean()
                
                logger.info(f"   Maior overflow: +{maior_overflow} bytes")
                logger.info(f"   Overflow médio: +{media_overflow:.1f} bytes")
                
                # Top 10 overflows
                logger.info(f"\n TOP 10 OVERFLOWS:")
                top_overflows = df_com_traducao[df_com_traducao['tem_overflow']].nlargest(10, 'diferenca_bytes')
                
                for idx, row in top_overflows.iterrows():
                    texto_orig = str(row.get('texto', ''))[:40] + ('...' if len(str(row.get('texto', ''))) > 40 else '')
                    texto_trad = str(row['texto_traduzido'])[:40] + ('...' if len(str(row['texto_traduzido'])) > 40 else '')
                    
                    logger.info(f"   {idx:4d}: +{row['diferenca_bytes']:2d}b ({row['percentual_diferenca']:+.1f}%)")
                    logger.info(f"         Original: '{texto_orig}'")
                    logger.info(f"         Tradução: '{texto_trad}'")
                    logger.info("")
        
        stats = {
            'total_traducoes': total_traducoes,
            'overflows': overflows,
            'taxa_overflow': taxa_overflow if total_traducoes > 0 else 0,
            'maior_overflow': df_com_traducao['diferenca_bytes'].max() if overflows > 0 else 0,
            'media_overflow': df_com_traducao[df_com_traducao['tem_overflow']]['diferenca_bytes'].mean() if overflows > 0 else 0
        }
    else:
        # Apenas estatísticas básicas sem comparação
        df_com_traducao = df[df['texto_traduzido'].notna() & (df['texto_traduzido'] != '')]
        total_traducoes = len(df_com_traducao)
        
        logger.info(f"\n ESTATÍSTICAS BÁSICAS:")
        logger.info(f"   Total de traduções: {total_traducoes}")
        logger.info(f"   Tamanho médio: {df_com_traducao['tamanho_bytes_traducao'].mean():.1f} bytes")
        logger.info(f"   Tamanho máximo: {df_com_traducao['tamanho_bytes_traducao'].max()} bytes")
        logger.info(f"   Tamanho mínimo: {df_com_traducao['tamanho_bytes_traducao'].min()} bytes")
        
        stats = {
            'total_traducoes': total_traducoes,
            'overflows': 0,
            'taxa_overflow': 0,
            'maior_overflow': 0,
            'media_overflow': 0
        }
    
    # Define arquivo de saída
    if arquivo_saida is None:
        nome_base = os.path.splitext(arquivo_csv)[0]
        arquivo_saida = f"{nome_base}_analisado.csv"
    
    # Salva arquivo processado
    logger.info(f"\n Salvando arquivo processado...")
    try:
        df.to_csv(arquivo_saida, index=False, encoding='utf-8')
        logger.info(f" Arquivo salvo: {arquivo_saida}")
    except Exception as e:
        logger.error(f" Erro ao salvar: {e}")
    
    return df, stats

def gerar_relatorio_excel(df, arquivo_excel, coluna_referencia=None):
    """
    Gera relatório Excel com formatação e destaque de overflows.
    
    Args:
        df (DataFrame): Dados processados
        arquivo_excel (str): Caminho para arquivo Excel de saída
        coluna_referencia (str): Nome da coluna de referência para comparação
    """
    
    try:
        # Importa bibliotecas necessárias para Excel
        try:
            from openpyxl import Workbook
            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.utils.dataframe import dataframe_to_rows
        except ImportError:
            logger.info(" Para gerar Excel com formatação, instale: pip install openpyxl")
            return False
        
        logger.info(f" Gerando relatório Excel...")
        
        # Cria workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Análise de Overflows"
        
        # Define estilos
        header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        overflow_fill = PatternFill(start_color="FFD2D2", end_color="FFD2D2", fill_type="solid")  # Vermelho claro
        warning_fill = PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid")   # Amarelo claro
        ok_fill = PatternFill(start_color="D5E8D4", end_color="D5E8D4", fill_type="solid")        # Verde claro
        
        # Adiciona dados
        for r in dataframe_to_rows(df, index=False, header=True):
            ws.append(r)
        
        # Formata cabeçalho
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center")
        
        # Identifica colunas importantes
        colunas = {col: idx + 1 for idx, col in enumerate(df.columns)}
        
        col_traducao = colunas.get('texto_traduzido')
        col_tamanho_trad = colunas.get('tamanho_bytes_traducao')
        col_tem_overflow = colunas.get('tem_overflow')
        col_diferenca = colunas.get('diferenca_bytes')
        
        # Aplica formatação condicional
        if col_tem_overflow and col_diferenca:
            logger.info(" Aplicando formatação condicional...")
            
            for row_idx in range(2, len(df) + 2):  # Pula cabeçalho
                tem_overflow = ws.cell(row=row_idx, column=col_tem_overflow).value
                diferenca = ws.cell(row=row_idx, column=col_diferenca).value
                
                if tem_overflow:
                    # Overflow crítico (>5 bytes) - Vermelho
                    if diferenca and diferenca > 5:
                        fill_color = overflow_fill
                    # Overflow moderado (1-5 bytes) - Amarelo
                    else:
                        fill_color = warning_fill
                    
                    # Destaca células da tradução e tamanho
                    if col_traducao:
                        ws.cell(row=row_idx, column=col_traducao).fill = fill_color
                    if col_tamanho_trad:
                        ws.cell(row=row_idx, column=col_tamanho_trad).fill = fill_color
                    
                    # Destaca diferença
                    if col_diferenca:
                        ws.cell(row=row_idx, column=col_diferenca).fill = fill_color
                        ws.cell(row=row_idx, column=col_diferenca).font = Font(bold=True)
                else:
                    # Sem overflow - Verde claro
                    if col_diferenca and diferenca is not None and diferenca <= 0:
                        ws.cell(row=row_idx, column=col_diferenca).fill = ok_fill
        
        # Ajusta largura das colunas
        for column in ws.columns:
            max_length = 0
            column_letter = column[0].column_letter
            
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            
            # Define largura com limites
            adjusted_width = min(max(max_length + 2, 10), 50)
            ws.column_dimensions[column_letter].width = adjusted_width
        
        # Adiciona aba de estatísticas
        ws_stats = wb.create_sheet("Estatísticas")
        
        # Cabeçalho das estatísticas
        stats_data = [
            ["Métrica", "Valor"],
            ["Total de traduções", len(df[df['texto_traduzido'].notna() & (df['texto_traduzido'] != '')])],
        ]
        
        if 'tem_overflow' in df.columns:
            overflows = df['tem_overflow'].sum()
            taxa = (overflows / len(df)) * 100 if len(df) > 0 else 0
            
            stats_data.extend([
                ["Overflows detectados", overflows],
                ["Taxa de overflow (%)", f"{taxa:.1f}%"],
            ])
            
            if overflows > 0:
                stats_data.extend([
                    ["Maior overflow (bytes)", df['diferenca_bytes'].max()],
                    ["Overflow médio (bytes)", f"{df[df['tem_overflow']]['diferenca_bytes'].mean():.1f}"],
                ])
        
        stats_data.extend([
            ["", ""],
            ["LEGENDA DE CORES", ""],
            ["Overflow crítico (>5 bytes)", "Vermelho"],
            ["Overflow moderado (1-5 bytes)", "Amarelo"], 
            ["Sem overflow", "Verde"],
        ])
        
        for row in stats_data:
            ws_stats.append(row)
        
        # Formata aba de estatísticas
        for cell in ws_stats[1]:
            cell.fill = header_fill
            cell.font = header_font
        
        # Adiciona cores na legenda
        ws_stats['B8'].fill = overflow_fill  # Vermelho
        ws_stats['B9'].fill = warning_fill   # Amarelo
        ws_stats['B10'].fill = ok_fill       # Verde
        
        # Salva arquivo
        wb.save(arquivo_excel)
        logger.info(f" Relatório Excel salvo: {arquivo_excel}")
        
        return True
        
    except Exception as e:
        logger.error(f" Erro ao gerar Excel: {e}")
        return False

def main():
    """Função principal"""
    
    # Configuração padrão
    arquivo_padrao = "./translated/strings_RADIO_traduzido.csv"
    
    # Verifica argumentos da linha de comando
    if len(sys.argv) < 2:
        logger.info(" USO:")
        logger.info(f"   python {sys.argv[0]} <arquivo.csv> [arquivo_saida.csv]")
        logger.info()
        logger.info(" EXEMPLOS:")
        logger.info(f"   python {sys.argv[0]} traducoes.csv")
        logger.info(f"   python {sys.argv[0]} traducoes.csv traducoes_analisadas.csv")
        logger.info()
        
        # Tenta usar arquivo padrão se existir
        if os.path.exists(arquivo_padrao):
            logger.info(f" Arquivo padrão encontrado: {arquivo_padrao}")
            resposta = input("Usar arquivo padrão? (s/N): ").strip().lower()
            if resposta in ['s', 'sim', 'y', 'yes']:
                arquivo_csv = arquivo_padrao
            else:
                return
        else:
            logger.error(f" Arquivo padrão não encontrado: {arquivo_padrao}")
            return
    else:
        arquivo_csv = sys.argv[1]
    
    # Arquivo de saída
    arquivo_saida = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Executa análise
    df, stats = analisar_overflows(arquivo_csv, arquivo_saida)
    
    if df is not None and stats is not None:
        # Pergunta se quer gerar Excel
        print("\n Deseja gerar relatório Excel com formatação? (s/N): ", end="")
        resposta = input().strip().lower()
        
        if resposta in ['s', 'sim', 'y', 'yes']:
            nome_base = os.path.splitext(arquivo_csv)[0]
            arquivo_excel = f"{nome_base}_relatorio.xlsx"
            
            coluna_ref = None
            for col in ['tamanho_bytes', 'bytes_disponiveis', 'tamanho_original']:
                if col in df.columns:
                    coluna_ref = col
                    break
            
            gerar_relatorio_excel(df, arquivo_excel, coluna_ref)
        
        logger.info(f"\n Análise concluída!")
        
        if stats['overflows'] > 0:
            logger.info(f" {stats['overflows']} overflows detectados - verifique as células destacadas")
        else:
            logger.info(f" Nenhum overflow detectado!")

if __name__ == "__main__":
    
    """
    Exemplo: python .\tools\overflow_checker.py .\translated\strings_RADIO_traduzido.csv out.csv
    """

    main()