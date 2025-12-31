python -m venv env
. env/bin/activate
python -m pip install -r requirements
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
python app.py
