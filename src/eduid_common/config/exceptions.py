class BadConfiguration(Exception):
    def __init__(self, message):
        Exception.__init__(self)
        self.value = message

    def __str__(self):
        return self.value
