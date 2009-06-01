
from google.appengine.ext import db
from basbrun import User

class CryptoEditorData(db.Model):
    user = db.ReferenceProperty(User)
    plugin = db.StringProperty(required=True)
    data = db.TextProperty(required=True)
    tlu = db.DateTimeProperty(auto_now_add=True)
    
