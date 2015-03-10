import logging
from eduid_lookup_mobile.config import read_configuration

conf = read_configuration()

if conf['LOG_PATH'] and not conf['LOG_PATH'] == "":
    logging.basicConfig(filename=conf['LOG_PATH'], level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.DEBUG)


# create logger
log = logging.getLogger('eduid_lookup_mobile')

#create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
log.addHandler(ch)
