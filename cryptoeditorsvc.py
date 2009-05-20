
from google.appengine.ext import db
from basbrun import User

class CryptoEditorData(db.Model):
    user = db.ReferenceProperty(User)
    plugin = db.StringReference(required=True)
    data = db.StringProperty(required=True)
    tlu = db.DateTimeProperty(auto_now_add=True)
    
class CryptoEditorRegistration(db.Model):
    user = db.ReferenceProperty(User)
    license = db.StringProperty(required=True)
    encrypted_license = db.StringProperty(default='')
    effective_to = db.DataTimeProperty(required=True)
    status = db.IntegerProperty(required=True)
