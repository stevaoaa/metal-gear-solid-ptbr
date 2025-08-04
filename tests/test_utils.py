import os
import sys
import unittest

import pandas as pd
from pathlib import Path

# Adiciona o diretório raiz ao sys.path para permitir importações internas
BASE_DIR = Path(__file__).parent.parent.absolute()
sys.path.append(str(BASE_DIR))
from tools.rebuild_text import MGSRebuilder



class TestRemoveAccentsSafe(unittest.TestCase):
    def setUp(self):
        self.rebuilder = MGSRebuilder()
        self.test_sentences = [
            "Como está funcionando o Traje de Infiltração?",
            "Estou bem e seco, mas é um pouco difícil#Nse mover.",
            "Aguente firme. Foi projetado para prevenir#Nhipotermia.",
            "Isto é o Alasca, sabe.",
            "Calma, estou grato.",
            "Se não fosse pelo seu traje e sua injeção,#Nteria virado um picolé lá#Nfora.",
            "Um peptídeo anticongelante, Snake.",
            "Todos os Soldados Genoma neste#Nexercício estão usando.",
            "B!ﾊr(",
            "Entendo. Fico aliviado em ouvir isso.#NJá testado, né?",
            "A propósito, como está indo a operação#Nde diversão?",
            "Dois F-16s decolaram de Galena#Ne estão indo na sua direção.",
            "O radar dos terroristas já deveria#Ntê-los detectado.",
            "Snake, há um elevador lá que você#Npode pegar para subir ao solo.",
            "Apenas terá que esperar o elevador#Ndescer. É melhor se esconder#Nem algum lugar."

        ]

    def test_remove_accents_and_print(self):
        print("\nResultados da Função remove_accents_safe:\n")
        for sentence in self.test_sentences:
            processed = self.rebuilder.remove_accents_safe(sentence)
            print(f"Original: {sentence}")
            print(f"Processado: {processed}")
            print("-" * 50)

    

    def test_remove_accents_simple(self):
        
        input_file = os.path.join('.', 'translated', 'strings_RADIO_traduzido.csv')
        output_file = os.path.join('.', 'translated', 'strings_RADIO_traduzido_sem_acentos.csv')

        # Lê CSV
        df = pd.read_csv(input_file, sep='\t')

        # Aplica transformação
        df['texto_traduzido'] = df['texto_traduzido'].apply(self.rebuilder.remove_accents_simple)

        # Salva resultado
        df.to_csv(output_file, sep='\t', index=False)
        print(f'Arquivo salvo em {output_file}')


if __name__ == "__main__":
    unittest.main()
