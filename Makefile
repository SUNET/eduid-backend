SOURCE=	src

reformat:
	isort --line-width 120 --atomic --project eduid_userdb --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)
