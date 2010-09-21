
import urllib
import uuid
import datetime
import wsgiref.handlers
from Crypto.Hash import MD5

from google.appengine.api import mail
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
#from google.appengine.api import memcache
from google.appengine.api import urlfetch

from basbrun import User
from cryptoeditorsvc import CryptoEditorData
from appengine_utilities.sessions import Session

debug = False
senderEmailAddress = 'philippe.chretien@gmail.com'
supportEmailAddress = 'philippe.chretien@gmail.com'

def checkLogin(handler):
    pageParams = {}
    handler.session = Session()        
    if handler.session.get('user'):
        user = db.get(handler.session.get('user'))
        pageParams = {'email': user.email}        
        
        if len(user.firstname) > 0 or len(user.lastname) > 0:
            pageParams['fullname'] = user.firstname + " " + user.lastname
            
        pageParams['expiration'] = user.expiration.date()
    
    # DEBUG
    # login and confirm pages
    if debug:
        query = db.GqlQuery('SELECT * FROM User ORDER BY email')
        users = [user for user in query]
        pageParams['users'] = users
    else:
        pageParams['users'] = []
            
    return pageParams

def getUser(handler):
    handler.session = Session()        
    if handler.session.get('user'):
        user = db.get(handler.session.get('user'))
        return user
    
    return None

def hash(password):
    # Hash the password ...
    md5 = MD5.new()
    md5.update(password)
    return md5.hexdigest()

class MainHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)            
        self.response.out.write( template.render('main.html', pageParams ))

class SuccessHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)   
        
#        for name in self.request.arguments():
#            values = self.request.get_all(name)
#            for val in values:
#                self.response.out.write(name + ' = ' + val + '<br>')

        tx = self.request.get('tx')
        if tx:
            url = "https://www.paypal.com/cgi-bin/webscr"
            form_fields = {'tx':tx,
                           'at':'_RQv379TRJgFvIUhpQ_XGusK4ET4GsTd3seyNk9trFYgm0tz6x7GqDjCGMO',
                           'cmd':'_notify-synch'
                           }
            form_data = urllib.urlencode(form_fields)
            result = urlfetch.fetch(url=url,
                            payload=form_data,
                            method=urlfetch.POST,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'})
            
            self.response.out.write(result.content)                 
            self.response.out.write( template.render('success.html', pageParams ))
                
class LoginHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)              
        self.response.out.write( template.render('login.html', pageParams ))
        
    def post(self):
        pageParams = checkLogin(self)
        
        email = self.request.get("email")
        password = self.request.get("password")
        
        query = db.GqlQuery('SELECT * FROM User where email = :1', email)
        user = query.get()
        
        if user is None or user.password != hash(password):
            pageParams['emailvalue'] = email
            pageParams['error'] = "Access denied."
            self.response.out.write( template.render('login.html', pageParams ))
            return
        
        if user.activated == 0:
            pageParams['emailvalue'] = email
            pageParams['error'] = "Your account has not been activated. Check your email for your activation code."
            self.response.out.write( template.render('login.html', pageParams ))
            return
            
        self.session = Session()
        self.session['user'] = user.key()
        self.redirect("/")

class LogoutHandler(webapp.RequestHandler):
    def get(self):
        self.session = Session()
        self.session.delete()            
        self.redirect('/login')
        
class ForgotHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)           
        self.response.out.write( template.render('forgot.html', pageParams ))
        
    def post(self):
        pageParams = checkLogin(self)
        email = self.request.get("email")
        
        user = None
        try:
            query = db.GqlQuery('SELECT * FROM User WHERE email = :1', email)
            user = query.get()
        except:
            None
        
        if user is None:
            pageParams['error'] = "Invalid email address."
            self.response.out.write( template.render('forgot.html', pageParams))
            return
        
        user.regkey = str(uuid.uuid4())  
        user.put()
              
        pageParams['key'] = user.regkey
        pageParams['emailvalue'] = user.email
        pageParams['firstnamevalue'] = user.firstname
        
        msg = template.render('forgot.eml', pageParams)            
        mail.send_mail(sender=senderEmailAddress,
                       to=email,
                       subject="CryptoEditor password reset confirmation",
                       body=msg)
        
        pageParams['message'] = "An email has been sent to " + email
        self.response.out.write( template.render('forgot.html', pageParams))
        
class ResetHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)
        
        pageParams['reg'] = self.request.get('reg')
        pageParams['key'] = self.request.get('key')
                                            
        self.response.out.write( template.render('reset.html', pageParams))
        
    def post(self):
        pageParams = checkLogin(self)
        
        email = self.request.get('email')
        key = self.request.get('key')
        password1 = self.request.get('password1')
        password2 = self.request.get('password2')
        
        pageParams['reg'] = self.request.get('email')
        pageParams['key'] = self.request.get('key')
                
        user = None
        try:
            query = db.GqlQuery('SELECT * FROM User WHERE regkey = :1', key)
            user = query.get()
        except:
            None
            
        if user is None or user.email != email:
            pageParams['error'] = "Invalid key or email address."
            self.response.out.write( template.render('reset.html', pageParams))
            return
        
        if password1 is None or len(password1) == 0:
            pageParams['error'] = "New password required."
            self.response.out.write( template.render('reset.html', pageParams))
            return
        
        if password2 is None or len(password2) == 0:
            pageParams['error'] = "New password confirmation required."
            self.response.out.write( template.render('reset.html', pageParams))
            return
        
        if password1 != password2:
            pageParams['error'] = "Password confirmation failed. Please enter your password again."
            self.response.out.write( template.render('reset.html', pageParams))
            return
        
        user.password = hash(password1)
        user.regkey = str(uuid.uuid4())
        user.activated = 1
        user.put()
        
        pageParams['message'] = "Password reset succeeded."
        self.response.out.write( template.render('reset.html', pageParams))            
                
class RegisterHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self) 
        self.response.out.write( template.render('register.html', pageParams))
        
    def post(self):
        email = self.request.get("email")
        password1=self.request.get("password1")
        password2=self.request.get("password2")
        firstname = self.request.get("firstname")
        lastname = self.request.get("lastname")
        
        pageParams = checkLogin(self)
        
        if email and len(email) > 0:
            pageParams['emailvalue'] = email
        if firstname and len(firstname) > 0:
            pageParams['firstnamevalue'] = firstname
        if lastname and len(lastname) > 0:
            pageParams['lastnamevalue'] = lastname
            
        if email is None or len(email) == 0:
            pageParams['error'] = "Email address is required."
            self.response.out.write( template.render('register.html', pageParams))
            return
        
        query = db.GqlQuery('SELECT * FROM User WHERE email = :1', email)
        user = query.get()
            
        if user:
            pageParams['error'] = "This user already exist"
            self.response.out.write( template.render('register.html', pageParams))
            return
        
        if password1 is None or len(password1) == 0:
            pageParams['error'] = "Password is required."
            self.response.out.write( template.render('register.html', pageParams))
            return
        
        if password2 is None or len(password2) == 0:
            pageParams['error'] = "Password confirmation is required."
            self.response.out.write( template.render('register.html', pageParams))
            return        

        if password1 != password2:
            pageParams['error'] = "Password confirmation failed. Please enter your password again."
            self.response.out.write( template.render('register.html', pageParams))
            return
        
        three_months = datetime.timedelta(days=90)
        
        user = User( regkey=str(uuid.uuid4()),
                     email=email,
                     password=hash(password1),
                     firstname=firstname,
                     lastname=lastname,
                     license=str(uuid.uuid4()),
                     status = 0,
                     expiration = datetime.datetime.now() + three_months )
        user.put()
        
        pageParams['key'] = user.regkey
        
        msg = template.render('confirm.eml', pageParams)            
        mail.send_mail(sender=senderEmailAddress,
                       to=email,
                       subject="CryptoEditor registration confirmation",
                       body=msg)
        
        pageParams['message'] = "A confirmation email has been sent to " + email
        self.response.out.write( template.render('register.html', pageParams))
            
        
class ProfileHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)
        
        user = getUser(self)
        if user is None:
            self.redirect("/login")
            return;
        
        pageParams['emailvalue'] = user.email
        pageParams['firstnamevalue'] = user.firstname
        pageParams['lastnamevalue'] = user.lastname
        pageParams['license'] = user.license
        pageParams['expiration'] = user.expiration.date()
                    
        self.response.out.write( template.render('profile.html', pageParams))
        
    def post(self):
        pageParams = checkLogin(self)        
        
        user = getUser(self)
        
        pageParams['emailvalue'] = user.email
        pageParams['firstnamevalue'] = user.firstname
        pageParams['lastnamevalue'] = user.lastname
        
        pageParams['license'] = user.license
        pageParams['expiration'] = user.expiration.date()
        
        click = self.request.get('click')
        if click == 'profile':
            firstname = self.request.get('firstname')
            lastname = self.request.get('lastname')
            
            user.firstname = firstname
            user.lastname = lastname
            user.put()
            
            pageParams['firstnamevalue'] = user.firstname
            pageParams['lastnamevalue'] = user.lastname
            
            if len(user.firstname) > 0 or len(user.lastname) > 0:
                pageParams['fullname'] = user.firstname + " " + user.lastname
            else:
                pageParams['fullname'] = None
                           
            pageParams['message'] = "Profile updated successfully."
            self.response.out.write( template.render('profile.html', pageParams))
            return
            
        elif click == 'email':
            email = self.request.get('email')
            
            if email is None or len(email) == 0:
                pageParams['error'] = "Email is required."
                self.response.out.write( template.render('profile.html', pageParams))
                return
            
            user.newemail = email
            user.regkey = str(uuid.uuid4())
            user.put()
            
            pageParams['newemail'] = user.newemail
            pageParams['key'] = user.regkey
        
            msg = template.render('changeemail.eml', pageParams)            
            mail.send_mail(sender=senderEmailAddress,
                           to=email,
                           subject="CryptoEditor email address confirmation.",
                           body=msg)
            
            pageParams['message'] = "Check your inbox to confirm your email address change."
            self.response.out.write( template.render('profile.html', pageParams))
            return           
            
        elif click == 'password':
            password1 = self.request.get('password1')
            password2 = self.request.get('password2')
            
            if password1 is None or len(password1) == 0:
                pageParams['error'] = "Password is required."
                self.response.out.write( template.render('profile.html', pageParams))
                return
                
            if password2 is None or len(password2) == 0:
                pageParams['error'] = "Password confirmation is required."
                self.response.out.write( template.render('profile.html', pageParams))
                return
                
            if password1 != password2:
                pageParams['error'] = "Password confirmation failed. Please enter your password again."
                self.response.out.write( template.render('profile.html', pageParams))
                return
            
            user.password = hash(password1)
            user.put()
            
            pageParams['message'] = "Password updated successfully."       
            self.response.out.write( template.render('profile.html', pageParams))
            return
        
class ConfirmHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)
        
        pageParams['reg'] = self.request.get('reg')
        pageParams['key'] = self.request.get('key')
                                            
        self.response.out.write( template.render('confirm.html', pageParams))
        
    def post(self):
        pageParams = checkLogin(self)        
        
        email = self.request.get('email')
        key = self.request.get('key')
        password = self.request.get('password')
        
        # For postback
        pageParams['key'] = self.request.get('key')
        
        if email and len(email) > 0 :
            pageParams['reg'] = email 
        if key and len(key) > 0 :
            pageParams['keyvalue'] = key
        
        user = None
        try:
            query = db.GqlQuery('SELECT * FROM User where regkey = :1', key)
            user = query.get()
        except:
            None
        
        if user is None or (user.email != email and user.newemail != email) or user.password != hash(password):
            pageParams['error'] = "Invalid email address, activation key or password"
            self.response.out.write( template.render('confirm.html', pageParams))
            return
        
        user.email = email
        user.newemail = None
        user.activated = 1        
        user.regkey = str(uuid.uuid4())
        user.put()
        
        if pageParams.has_key('email'):
            pageParams['email'] = user.email
            
        pageParams['license'] = user.license
        pageParams['emailvalue'] = user.email
        pageParams['firstnamevalue'] = user.firstname
        
        msg = template.render('sendkey.eml', pageParams)            
        mail.send_mail(sender='CryptoEditor <'+senderEmailAddress+'>',
                       to=user.email,
                       subject="CryptoEditor - Registration key",
                       body=msg)
        
        pageParams['message'] = "Account activated successfully."
        self.response.out.write( template.render('confirm.html', pageParams))
        
class ContactHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)             
        self.response.out.write( template.render('contact.html', pageParams))
        
    def post(self):
        fullname = self.request.get("fullname")
        email1 = self.request.get("email1")
        email2 = self.request.get("email2")        
        subject = self.request.get("subject")
        body = self.request.get("body")
        
        pageParams = checkLogin(self)
        pageParams['email1'] =  self.request.get('email1')
        pageParams['email2'] =  self.request.get('email2')       
        pageParams['fullname'] =  self.request.get('fullname')
        pageParams['subject'] =  self.request.get('subject')
        pageParams['body'] =  self.request.get('body')
        
        if fullname is None or len(fullname) == 0:
            pageParams['error'] = "Please provide your name."
            self.response.out.write( template.render('contact.html', pageParams))
            return
        
        if email1 is None or len(email1) == 0:
            pageParams['error'] = "Email address required."
            self.response.out.write( template.render('contact.html', pageParams))
            return
        
        if email2 is None or len(email2) == 0:
            pageParams['error'] = "Email address confirmation required."
            self.response.out.write( template.render('contact.html', pageParams))
            return
        
        if email1 != email2:
            pageParams['error'] = "Email confirmation failed. Please enter your email again."
            self.response.out.write( template.render('contact.html', pageParams))
            return
        
        if subject is None or len(subject) == 0:
            pageParams['error'] = "Subject required."
            self.response.out.write( template.render('contact.html', pageParams))
            return
        
        if body is None or len(body) == 0:
            pageParams['error'] = "Your message is empty."
            self.response.out.write( template.render('contact.html', pageParams))
            return
        
        msg = template.render('contact.eml', pageParams)            
        mail.send_mail(sender='CryptoEditor <'+senderEmailAddress+'>',
                       to=supportEmailAddress,
                       subject=subject,
                       body=msg)
        
        pageParams['message'] = "Your message has been sent with success."
        self.response.out.write( template.render('contact.html', pageParams))
        
class GetProfileHandler(webapp.RequestHandler):
    def post(self):
        pageParams = {}
        
        email = self.request.get('email')
        query = db.GqlQuery('SELECT * FROM User where email = :1', email)
        user = query.get()
        
        if user is None:
            pageParams['error'] = "USER_DOES_NOT_EXIST"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        pageParams['user'] = user
        self.response.headers['Content-Type'] = 'text/xml'
        self.response.out.write( template.render('getprofile.xml', pageParams))
        
class PutLicenseHandler(webapp.RequestHandler):
    def post(self):
        pageParams = {}
        
        email = self.request.get('email')
        license = self.request.get('license')
        encrypted_license = self.request.get('encrypted_license')
        sendmail = self.request.get('sendmail')
        
        query = db.GqlQuery('SELECT * FROM User where email = :1 and license = :2', email, license)
        user = query.get()
        
        if user is None:
            pageParams['error'] = "USER_DOES_NOT_EXIST"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        if user.encrypted_license and len(user.encrypted_license) > 0 and encrypted_license != user.encrypted_license:
            pageParams['error'] = "INVALID_PASSWORD"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
            
        user.encrypted_license = encrypted_license
        user.status = 1;
        user.put()
        
        if sendmail == 'yes':
            msg = template.render('putlicense.eml', pageParams)            
            mail.send_mail(sender='CryptoEditor <'+senderEmailAddress+'>',
                           to=user.email,
                           subject='CryptoEditor synchronization activated',
                           body=msg)
        
        pageParams['user'] = user
        self.response.headers['Content-Type'] = 'text/xml'
        self.response.out.write( template.render('getprofile.xml', pageParams))

class LoadHandler(webapp.RequestHandler):
    def post(self):
        pageParams = {}
        
        email = self.request.get('email')
        license = self.request.get('license')
        plugin = self.request.get('plugin')
        
        query = db.GqlQuery('SELECT * FROM User where email = :1 and license = :2', email, license)
        user = query.get()
        
        # Check user
        if user is None:
            pageParams['error'] = "USER_DOES_NOT_EXIST"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        # Check status
        if user.status == 0:
            pageParams['error'] = "USER_NOT_ACTIVATED"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        # Check expiration
        if user.expiration + datetime.timedelta(days=1) < datetime.datetime.now():
            pageParams['error'] = "USER_EXPIRED"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        query = db.GqlQuery('SELECT * FROM CryptoEditorData where user = :1 and plugin = :2', user, plugin)
        dataObj = query.get()
        
        data = ''
        if dataObj:
            data = dataObj.data
              
        self.response.headers['Content-Type'] = 'text/xml'
        self.response.out.write(data)
        
class SaveHandler(webapp.RequestHandler):
    def post(self):
        pageParams = {}
        
        email = self.request.get('email')
        license = self.request.get('license')
        plugin = self.request.get('plugin')
        data = self.request.get('data');
        
        query = db.GqlQuery('SELECT * FROM User where email = :1 and license = :2', email, license)
        user = query.get()
        
        # Check user
        if user is None:
            pageParams['error'] = "USER_DOES_NOT_EXIST"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        # Check status
        if user.status == 0:
            pageParams['error'] = "USER_NOT_ACTIVATED"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        # Check expiration
        if user.expiration + datetime.timedelta(days=1)< datetime.datetime.now():
            pageParams['error'] = "USER_EXPIRED"
            self.response.headers['Content-Type'] = 'text/xml'
            self.response.out.write( template.render('response.xml', pageParams))
            return
        
        query = db.GqlQuery('SELECT * FROM CryptoEditorData where user = :1 and plugin = :2', user, plugin)
        dataObj = query.get()
        
        # Check data
        
        if dataObj is None:
            dataObj = CryptoEditorData(user=user, plugin=plugin, data=data)
        else:
            dataObj.data = data;
            dataObj.tlu = datetime.datetime.now()
            
        dataObj.put() 
        pageParams = {}
        self.response.headers['Content-Type'] = 'text/xml'
        self.response.out.write( template.render('response.xml', pageParams))
 
class PingHandler(webapp.RequestHandler):
    def get(self):
        pageParams = {}
        self.response.out.write( template.render('ping.html', pageParams))
        
class NewsHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)
        base = self.request.get('base')
        if base:
            base = 'base' + base + '.html'
        else:
            base = 'master.html'
            
        pageParams['base'] = base
        self.response.out.write( template.render('news.html', pageParams))
        
class FaqHandler(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)        
        self.response.out.write( template.render('faq.html', pageParams))

      
class MailJobHandler(webapp.RequestHandler):
    def get(self):
        mail.send_mail(sender='CryptoEditor <'+senderEmailAddress+'>',
                           to="philippe.chretien@gmail.com",
                           subject='MailJob',
                           body="CryptoEditor MailJob Service")
        
        return
        
class StartNow(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)        
        self.response.out.write( template.render('startnow.html', pageParams))
        
class How(webapp.RequestHandler):
    def get(self):
        pageParams = checkLogin(self)        
        self.response.out.write( template.render('how.html', pageParams))
      
def main():
    application = webapp.WSGIApplication([('/', MainHandler), 
                                          ('/login', LoginHandler),
                                          ('/register', RegisterHandler),
                                          ('/confirm', ConfirmHandler),
                                          ('/myprofile', ProfileHandler),
                                          ('/logout', LogoutHandler),
                                          ('/forgot', ForgotHandler),
                                          ('/reset', ResetHandler),
                                          ('/contact', ContactHandler),
                                          ('/getprofile', GetProfileHandler),
                                          ('/putlicense', PutLicenseHandler),
                                          ('/load', LoadHandler),
                                          ('/save', SaveHandler),
                                          ('/ping', PingHandler),
                                          ('/news', NewsHandler),
                                          ('/faq', FaqHandler),
                                          ('/success', SuccessHandler),
                                          ('/startnow', StartNow),
                                          ('/how', How),
                                          ('/mailjob', MailJobHandler) ], debug=True)
    
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
    main()
    
    