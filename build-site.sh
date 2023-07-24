#! /bin/bash
set -e
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -Ur paper-requirements.txt
jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace paper.ipynb
jupyter nbconvert --execute --to notebook --inplace paper.ipynb
jupyter nbconvert paper.ipynb --TagRemovePreprocessor.remove_cell_tags='html_only' --TagRemovePreprocessor.remove_input_tags='latex_only' --to pdf --template ./template --output-dir _site --output index
jupyter nbconvert paper.ipynb --TagRemovePreprocessor.remove_input_tags='html_only' --TagRemovePreprocessor.remove_cell_tags='latex_only' --to html --template classic --output-dir _site --output index
#ghp-import -n -p -f _site
jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace paper.ipynb
