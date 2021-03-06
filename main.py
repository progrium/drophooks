from google.appengine.ext import webapp, db
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch
from google.appengine.api import taskqueue
from django.utils import simplejson as json

from dropbox import client, rest, auth
from oauth.oauth import OAuthToken
from google.appengine.api import memcache

import urllib
import base64

POLL_INTERVAL = 60 # seconds

config = auth.Authenticator.load_config("drophooks.ini")

class DropboxUser(db.Model):
    uid = db.StringProperty()
    email = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    callback_url = db.StringProperty(default='')
    size = db.StringProperty()

    @classmethod
    def get_by_uid(cls, uid):
        user = cls.all().filter('uid =', uid).get()
        if user is None:
            user = cls(uid=uid)
            user.put()
        return user
    
    @classmethod
    def get_current(cls, handler):
        uid = handler.request.cookies.get('uid')
        if uid is not None:
            return cls.all().filter('uid =', uid).get()
        else:
            return None

class MainHandler(webapp.RequestHandler):
    def get(self):
        user = DropboxUser.get_current(self)
        self.response.out.write(template.render('templates/main.html', locals()))
    
    def post(self):
        user = DropboxUser.get_current(self)           
        if user:
            user.callback_url = self.request.get('callback_url')
            user.put()
        self.redirect('/')

class LoginHandler(webapp.RequestHandler):
    def get(self):
        dba = auth.Authenticator(config)
        req_token = dba.obtain_request_token()
        base64_token = urllib.quote(base64.b64encode(req_token.to_string()))
        self.redirect(dba.build_authorize_url(req_token, callback="http://%s/callback/%s" % (self.request.host, base64_token) ))

class LoginCallbackHandler(webapp.RequestHandler):
    def get(self, token):
        dba = auth.Authenticator(config)
        req_token = OAuthToken.from_string(base64.b64decode(urllib.unquote(token)))
        uid = self.request.get('uid')
        self.response.headers.add_header('Set-Cookie', 'uid=%s; path=/' % uid)
        
        token = dba.obtain_access_token(req_token, '')
        
        db_client = client.DropboxClient(config['server'], config['content_server'], config['port'], dba, token)
        account = json.loads(db_client.account_info().body)
        
        user = DropboxUser.get_by_uid(uid)
        user.oauth_token = token.key
        user.oauth_token_secret = token.secret
        user.email = account['email']
        user.put()
        
        if user.size is None:
            taskqueue.add(url='/tasks/poll', params={'uid': uid})
        
        self.redirect('/')
    
class LogoutHandler(webapp.RequestHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'uid=; path=/; expires=Thu, 01-Jan-1970 00:00:01 GMT;')
        self.redirect(self.request.get('redirect_to'))

class GrueHandler(webapp.RequestHandler):
    def get(self):
        
        user = DropboxUser.get_current(self)
        
        if user:
            token = OAuthToken(user.oauth_token, user.oauth_token_secret)
            dba = auth.Authenticator(config)
            db_client = client.DropboxClient(config['server'], config['content_server'], config['port'], dba, token)

            dirinfo = json.loads(db_client.metadata('dropbox', '').body)
            
            if 'contents' in dirinfo:
                self.response.out.write(dirinfo['contents'])
            else: 
                self.response.out.write('no contents, bro')
        else:
            print "There was no user, bro."
        
class PollTask(webapp.RequestHandler):
    def post(self):
        uid = self.request.get('uid')
        if uid is not None:
            taskqueue.add(url='/tasks/poll', params={'uid': uid}, countdown=POLL_INTERVAL)
            user = DropboxUser.get_by_uid(uid)
            token = OAuthToken(user.oauth_token, user.oauth_token_secret)
            dba = auth.Authenticator(config)
            db_client = client.DropboxClient(config['server'], config['content_server'], config['port'], dba, token)
            account_info = json.loads(db_client.account_info().body)
            size = str(account_info['quota_info']['normal'])

            if user.size != size:
                params = {'changed': 'yeah'}
                urlfetch.fetch(url=user.callback_url, payload=urllib.urlencode(params), method='POST')

            user.size = size
            user.put()



def main():
    application = webapp.WSGIApplication([
        ('/', MainHandler),
        ('/grue/rocks', GrueHandler),
        ('/tasks/poll', PollTask),
        ('/login', LoginHandler),
        ('/logout', LogoutHandler),
        ('/callback/(.*)', LoginCallbackHandler),     ], debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
