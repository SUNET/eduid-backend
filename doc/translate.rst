Enter directory src/eduid_webapp

pybabel extract -F babel.cfg -k lazy_gettext -o messages.pot .

Upload messages.pot to Transifex. Translate and download languange specific files.

pybabel compile -d translations

