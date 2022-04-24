#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import re
import os
import jinja2
import random
import hashlib
import string
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env=jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

SECRET="ias1db1ul``lmpo2ss,12ib123.ahsadlagse129022"

USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_PW=re.compile(r"^.{3,20}$")
USER_EL=re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return USER_PW.match(password)

def valid_email(email):
    return USER_EL.match(email)

def make_hash_cookie(s):
    return hmac.new(SECRET,s).hexdigest()

def set_secure_cookie(s):
    return "%s|%s"%(s,make_hash_cookie(s))

def check_secure_cookie(c):
    try:
        val=c.split('|')[0]
        if(c==set_secure_cookie(val)):
            return val
    except:
        return None


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt=h.split(',')[1]
    if h == make_pw_hash(name,pw,salt):
        return True

def is_present(username):
    x=User.all().filter('username = ',username).get()
    if x:
        return x


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template,**params):
        t=jinja_env.get_template(template)
        self.write(t.render(params))

class User(db.Model):
    username=db.StringProperty(required = True)
    password=db.StringProperty(required = True)
    email=db.StringProperty()
    created=db.DateTimeProperty(auto_now_add=True)

class NewsFeed(db.Model):
    username=db.StringProperty(required = True)
    chat=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)


class MainHandler(Handler):
    def error(self,name="",name_error="",password_error="",verify_error="",email_error="",email=""):
        self.render_str("sign_up.html",
                        name=name,
                        name_error=name_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error,
                        email=email
                        )
    
    def get(self):
        self.error()

    def post(self):
        
        name_error="invalid username"
        password_error="invalid password"
        verify_error="your password's didn't match"
        email_error="invalid email id"
        
        username=self.request.get('username')
        password=self.request.get('password')
        verify=self.request.get('verify')
        email=self.request.get('email')

        # user input validation starts

        if valid_username(username):
            name_error=""

        if is_present(username):
            name_error="the username already exists"

        if email:
            if valid_email(email):
                email_error=""
        else:
            email_error=""

        if password and valid_password(password):
            password_error=""
            if password==verify:
                verify_error=""
        else:
            verify_error=""
            
        #user input validation ends

        if name_error=="" and password_error=="" and verify_error=="" and email_error=="":
            password = make_pw_hash(username,password)
            a = User(username=username,password=password,email=email)
            a.put()
            self.response.headers.add_header('Set-Cookie',"user_id=%s"%set_secure_cookie(str(a.key().id())))
            self.redirect('/welcome')
        else:
            self.error(username,name_error,password_error,verify_error,email_error,email)


class LoginHandler(Handler):
    def error(self,error=""):
        self.render_str('login.html',error=error)
    
    def get(self):
        self.error()

    def post(self):
        username=self.request.get('username')
        password=self.request.get('password')
        user=is_present(username)
        if user and password:
            if valid_pw(username,password,user.password):
                self.response.headers.add_header('Set-Cookie',"user_id=%s"%set_secure_cookie(str(user.key().id())))
                self.redirect('/welcome')
            else:
                self.error('invalid login')
        else:
            self.error('invalid login')
        
class LogoutHandler(Handler):
    def get(self):
        self.response.delete_cookie('user_id')
        self.redirect('/login')


class Message(db.Model):
    transmitter=db.StringProperty(required = True)
    receiver=db.StringProperty(required = True)
    message=db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class WelcomeHandler(Handler):
    def get(self):
        cookie=self.request.cookies.get('user_id')
        user_id=check_secure_cookie(cookie)
        if user_id:
            username=User.get_by_id(int(user_id)).username
            curser=db.GqlQuery('SELECT * FROM NewsFeed ORDER BY created DESC LIMIT 35')
            self.render_str('welcome.html',username=username,curser=curser)
        else:
            self.redirect('/login')

    def post(self):
        news = self.request.get('news')
        cookie=self.request.cookies.get('user_id')
        user_id=check_secure_cookie(cookie)
        if user_id and news:
            a=NewsFeed(username=User.get_by_id(int(user_id)).username,chat=news)
            a.put()
        self.redirect('/welcome')


class MessageHandler(Handler):
    
    def get(self):
        cookie=self.request.cookies.get('user_id')
        user_id=check_secure_cookie(cookie)
        if user_id:
            username=User.get_by_id(int(user_id)).username
            self.render_str('index.html',username=username)
        else:
            self.redirect('/login')

    def post(self):
        cookie=self.request.cookies.get('user_id')
        user_id=check_secure_cookie(cookie)
        to_user = self.request.get('to_user')
        message = self.request.get('message')
        error="username doesn't exist"
        need="fill both the entries"
        if not user_id:
            self.redirect('/login')
            return
            
        if to_user and message:
            x=is_present(to_user)
            if x:
                a=Message(transmitter=User.get_by_id(int(user_id)).username,receiver=x.username,message=message)
                a.put()
                self.render_str('index.html',username=User.get_by_id(int(user_id)).username,success="your message has been sent")
            else:
                self.render_str('index.html',username=User.get_by_id(int(user_id)).username,error=error)
        else:
            self.render_str('index.html',username=User.get_by_id(int(user_id)).username,error=need)

def is_transmitter(username):
    x=Message.all().filter('transmitter = ',username).order("-created")
    if x:
        return x

def is_reciever(username):
    x=Message.all().filter('receiver = ',username).order("-created")
    if x:
        return x

class InboxHandler(Handler):
    def get(self):
        cookie=self.request.cookies.get('user_id')
        user_id=check_secure_cookie(cookie)
        if user_id:
            username=User.get_by_id(int(user_id)).username
            self.render_str('inbox.html',username=username,curser=is_reciever(username))
        else:
            self.redirect('/login')

class OutboxHandler(Handler):
    def get(self):
        cookie=self.request.cookies.get('user_id')
        user_id=check_secure_cookie(cookie)
        if user_id:
            username=User.get_by_id(int(user_id)).username
            self.render_str('outbox.html',username=username,curser=is_transmitter(username))
        else:
            self.redirect('/login')

class TotalHandler(Handler):
    def get(self):
        result = db.GqlQuery("Select * from User")
        self.write(result.count(1000000))


app = webapp2.WSGIApplication([
    ('/signup', MainHandler),
    ('/welcome',WelcomeHandler),
    ('/login',LoginHandler),
    ('/logout',LogoutHandler),
    ('/message',MessageHandler),
    ('/inbox',InboxHandler),
    ('/outbox',OutboxHandler),
    ('/totalusers',TotalHandler)
], debug=True)






















