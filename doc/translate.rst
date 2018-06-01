Enter directory src/eduid_webapp

pybabel extract -F babel.cfg -k lazy_gettext -o messages.pot .

Upload messages.po to Transifex. Translate and download languange specific files.

pybabel compile -d translations

