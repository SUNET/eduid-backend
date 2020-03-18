SOURCE=	eduid_msg

reformat:
	isort --line-width 120 --atomic --project eduid_msg --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)
