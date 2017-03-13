from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    email = db.StringProperty()

class Post(db.Model):
    author = db.ReferenceProperty(User, collection_name='posts')
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
