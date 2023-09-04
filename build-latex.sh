#! /bin/bash
set -e
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -Ur paper-requirements.txt
jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace paper.ipynb
jupyter nbconvert --execute --to notebook --inplace paper.ipynb
jupyter nbconvert paper.ipynb --TagRemovePreprocessor.remove_cell_tags='html_only' --TagRemovePreprocessor.remove_cell_tags='no_latex' --TagRemovePreprocessor.remove_input_tags='latex_only' --to latex --template ./templates/latex --output-dir _site --output index
jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace paper.ipynb
cp paper.bib _site/