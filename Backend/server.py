
class Server:
    
    def __init__(self):
        self.inboxes = {}
    

    def register(self, name):
        self.inboxes[name] = {}

    
    def registerWithToken(self, token):
        self.inboxes[token] = {}