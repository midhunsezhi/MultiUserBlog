import os
import webapp2
import jinja2
import hashlib
import string
import random
import hmac
from util import *
from models import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))


class NewPost(Handler):
    def render_form(self, subject="", content="", error=""):
        self.render('new_post.html', subject=subject, content=content, error=error)

    def get(self):
        user_hash = self.request.cookies.get('user_id')
        user_id = validate_cookie(user_hash)
        if user_id:
            self.render_form()
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_hash = self.request.cookies.get('user_id')
        user_id = validate_cookie(user_hash)

        if subject and content and user_id:
            key = db.Key.from_path('User', int(user_id))
            user = db.get(key)
            post = Post(author=user, subject=subject, content=content)
            post.put()
            self.redirect("/post/%s" % str(post.key().id()))
        else:
            self.render_form(subject, content, "Both subject and content are required!")


class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        user_hash = self.request.cookies.get('user_id')
        active_user = bool(validate_cookie(user_hash))
        self.render('landing_page.html', posts=posts, active_user=active_user)

class DisplayPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        self.render('post_page.html', post=post)

class UserRegistration(Handler):
    def render_form(self, username="", password="", verify="", email="", error=""):
        self.render('sign_up.html', username=username, password=password, verify=verify, email=email, error=error)
    def get(self):
        self.render_form()
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        if username and password and verify and (password == verify):
            def make_salt():
                return ''.join(random.choice(string.letters) for x in xrange(5))

            usersWithName = User.gql("where username = :1", username).get()
            if usersWithName is None:
                #hash password and save to db
                salt = make_salt()
                password_hash = hashlib.sha256(username + password + salt).hexdigest() + ',' + salt
                user = User(username=username, password=password_hash, email=email)
                user.put()
                # set the user cookie
                user_id = user.key().id()
                id_hash = str(user_id) + '|' + hmac.new(SECRET, str(user_id)).hexdigest()
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % id_hash)

                self.redirect("/")
            else:
                error = "Username already exists, please use a different name"
                self.render_form(username, password, verify, email, error)
        else:
            error = "Please make sure that all fields are valid"
            self.render_form(username, password, verify, email, error)

class LoginPage(Handler):
    def render_form(self, username="", password="", error=""):
        self.render('login.html', username=username, password=password, error=error)

    def get(self):
        self.render_form()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if username and password:
            user = User.gql("where username = :1", username).get()
            if user is not None:
                password_hash = user.password
                salt = password_hash.split(',')[1]
                if hashlib.sha256(username + password + salt).hexdigest() + ',' + salt == password_hash:
                    # set the user cookie
                    user_id = user.key().id()
                    id_hash = str(user_id) + '|' + hmac.new(SECRET, str(user_id)).hexdigest()
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % id_hash)

                    self.redirect("/")
                else:
                    error = "Incorrect credentials"
                    self.render_form(username, password, error)
            else:
                error = "Account doesn't exist"
                self.render_form(username, password, error)
        else:
            error = "Both username and password are required"
            self.render_form(username, password, error)

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/login")

class AddComment(Handler):
    def post(self):
        user_hash = self.request.cookies.get('user_id')
        user_id = validate_cookie(user_hash)
        if user_id:
            user_key = db.Key.from_path('User', int(user_id))
            user = db.get(user_key)
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id))
            post = db.get(post_key)
            content = self.request.get('content')
            comment = Comment(author=user, post=post, content=content)
            comment.put()
            self.redirect("/post/%s" % str(post.key().id()))
        else:
            self.redirect("/login")

class LikeHandler(Handler):
    def post(self):
        user_hash = self.request.cookies.get('user_id')
        user_id = validate_cookie(user_hash)
        if user_id:
            user_key = db.Key.from_path('User', int(user_id))
            user = db.get(user_key)
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id))
            post = db.get(post_key)
            if (post.author.key() != user.key()) and (user_key not in post.likes):
                post.likes.append(user_key)
                post.put()
            self.redirect("/post/%s" % str(post.key().id()))
        else:
            self.redirect("/login")



app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', NewPost),
    ('/post/([0-9]+)', DisplayPost),
    ('/signup', UserRegistration),
    ('/login', LoginPage),
    ('/logout', Logout),
    ('/addcomment', AddComment),
    ('/like', LikeHandler)
], debug=True)
