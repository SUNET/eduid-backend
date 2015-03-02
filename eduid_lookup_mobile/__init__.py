import logging
#from eduid_lookup_mobile import config

#conf = config.read_configuration()

# TODO the log file path and level from config?
logging.basicConfig(filename='/var/log/eduid/eduid_lookup_mobile.log', level=logging.DEBUG)
#logging.basicConfig(filename='./eduid_lookup_mobile.log', level=logging.DEBUG)

# create logger
log = logging.getLogger('eduididproofing_mobile')

#create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
log.addHandler(ch)
