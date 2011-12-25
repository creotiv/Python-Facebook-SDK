#!/usr/bin/env python
#
# Copyright 2012 Andrey Nikishaev
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Python client library for the Facebook Platform.

This client library is designed to support the Facebook Authentication and 
Graph API. Read more about the Graph API at 
http://developers.facebook.com/docs/api. 

Example of use:

   fb       = Facebook.init(request,app_id,app_secret)
   session  = fb.getSession()
   graph    = fb.getGraph()
   user     = graph.get_object("me")
   friends  = graph.get_connections(user["id"], "friends")

"""

import cgi
import hashlib
import time
import urllib
import hmac
import base64
import string
import hashlib

try:
    import json
    _json_decode = lambda s: json.loads(_unicode(s))
    _json_encode = lambda v: json.dumps(v)
except ImportError:
    try:
        import simplejson
        _json_decode = lambda s: simplejson.loads(_unicode(s))
        _json_encode = lambda v: simplejson.dumps(v)
    except ImportError:
        try:
            # For Google AppEngine
            from django.utils import simplejson
            _json_decode = lambda s: simplejson.loads(_unicode(s))
            _json_encode = lambda v: simplejson.dumps(v)
        except:
            raise Exception("A JSON parser is required, e.g., simplejson at "
                    "http://pypi.python.org/pypi/simplejson/")
        
def json_encode(value):
    """JSON-encodes the given Python object."""
    return _json_encode(value)


def json_decode(value):
    """Returns Python objects for the given JSON string."""
    return _json_decode(value)


class Facebook(object):
    """
        Facebook SDK
    
        Example:

           fb       = Facebook.init(request,app_id,app_secret)
           session  = fb.getSession()
           graph    = fb.getGraph()
           user     = graph.get_object("me")
           friends  = graph.get_connections(user["id"], "friends")

    """

    def init(self,request_or_cookie, app_id, app_secret):
        """
            Init Facebook session
            
            request_or_cookie - dictionary object
        """    
        self.app_id     = app_id
        self.app_secret = app_secret
        self.graph      = None
        self.session    = self.getSession(request_or_cookie, app_id, app_secret)
    
        if not session:
            return False
        
        self.graph = GraphAPI(session['access_token'])    
        return True
    
    def generate_sig(self,sess,secret):
        """
            Generate sig from signed_request.
        """
        base_string = ''
        for key,value in sess.iteritems():
            base_string += str(key)+'='+str(value)
        base_string += str(secret);
        return hashlib.md5(base_string).hexdigest();

    def get_access_token_from_signed_request(self,data,secret):
        """
            Get session from signed_request.
            More info: http://developers.facebook.com/docs/authentication/signed_request/
        """
        try:
            encoded_sig, payload = data.split('.', 2) 
            
            a = string.maketrans('-_','+/')
            sig = base64.urlsafe_b64decode(str(encoded_sig)+'=='.translate(a))
            data = json_decode(base64.urlsafe_b64decode(str(payload+'==').translate(a)))

            if data['algorithm'].upper() != 'HMAC-SHA256':
                return None

            h = hmac.new(secret, payload, hashlib.sha256)
            expected_sig = h.digest()
            if sig != expected_sig: 
                return None

        except Exception,e:
            return None
            
        return data

    def get_access_token_from_cookies(cookies,app_id,app_secret):
        """
            Get session from Facebook cookie
            
            To use Facebook cookies you must add to P3P header:
            self.response.headers['P3P']='CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"'
            
            and call with Javascript SDK on first canvas load:
            
            //session getted from signed_request during canvas load
            FB.init({
                appId  : '***********',
                status : true, // check login status
                cookie : true, // enable cookies to allow the server to access the session
                xfbml  : true,  // parse XFBML
                session: 'json_encoded_session_getted_on_backend',
                channelUrl : location.href+'/channel.html'
            });
            
        """
        cookie = cookies.get("fbs_" + app_id, "")
        if not cookie: return None
        try:
            args = dict((k, v[-1]) for k, v in cgi.parse_qs(cookie.strip('"')).items())
            payload = "".join(k + "=" + args[k] for k in sorted(args.keys())
                              if k != "sig")
            sig = hashlib.md5(payload + app_secret).hexdigest()
            expires = int(args["expires"])
            if sig == args.get("sig") and (expires == 0 or time.time() < expires):
                return args
            else:
                return None
        except:
            return None
            
    def get_access_token_from_code(cookies,app_id,app_secret):
        pass
            
    def get_app_access_token(self, app_id=None, app_secret=None):
        """
            Generates application access_token.
        """ 
        app_id     = app_id or self.app_id;
        app_secret = app_secret or self.app_secret 
        return app_id+'|'+app_secret;

    def getSession(self,request_or_cookie=None, app_id=None, app_secret=None):
        """
            Get session from signed_request or cookies
        """
        if self.session:
            return self.session
            
        if (not app_id) and (not app_secret) and (not request_or_cookie):
            return None

        signed_request = request_or_cookies.get('signed_request')
        cookies        = request_or_cookies.get("fbsr_" + app_id, "")
        session        = None
        
        if signed_request:
            data = self.get_access_token_from_signed_request(signed_request,app_secret)
            if data.has_key('oauth_token') and data.has_key('user_id'):
                res = {
                    'access_token':data['oauth_token'],
                    'expires':data['expires'],
                    'uid':data['user_id']
                }
                sig = self.generate_sig(res,secret)
                res['sig'] = sig
                session = res
            
        
        if not session and cookies:
            session = self.get_access_token_from_cookies(cookies,app_id,app_secret)
            if (not data.has_key('oauth_token')) or (not data.has_key('user_id')):
                session = None
                
        if not session:
            session = self.get_app_access_token(app_id,app_secret)
        
        self.session = session
        
        return session
        
    def getGraph(self):
        if not graph:
           raise FacebookError('Facebook access_token is undefined.')
        return self.graph
        

class GraphAPI(object):
    """A client for the Facebook Graph API.

    See http://developers.facebook.com/docs/api for complete documentation
    for the API.

    The Graph API is made up of the objects in Facebook (e.g., people, pages,
    events, photos) and the connections between them (e.g., friends,
    photo tags, and event RSVPs). This client provides access to those
    primitive types in a generic way. For example, given an OAuth access
    token, this will fetch the profile of the active user and the list
    of the user's friends:

       graph = facebook.GraphAPI(access_token)
       user = graph.get_object("me")
       friends = graph.get_connections(user["id"], "friends")

    You can see a list of all of the objects and connections supported
    by the API at http://developers.facebook.com/docs/reference/api/.

    You can obtain an access token via OAuth or by using the Facebook
    JavaScript SDK. See http://developers.facebook.com/docs/authentication/
    for details.

    If you are using the JavaScript SDK, you can use the
    get_user_from_cookie() method below to get the OAuth access token
    for the active user from the cookie saved by the SDK.
    """
    def __init__(self, access_token=None):
        self.access_token = access_token

    def get_object(self, id, **args):
        """Fetchs the given object from the graph."""
        return self.request(id, args)

    def get_objects(self, ids, **args):
        """Fetchs all of the given object from the graph.

        We return a map from ID to object. If any of the IDs are invalid,
        we raise an exception.
        """
        args["ids"] = ",".join(ids)
        return self.request("", args)

    def get_connections(self, id, connection_name, **args):
        """Fetchs the connections for given object."""
        return self.request(id + "/" + connection_name, args)

    def put_object(self, parent_object, connection_name, **data):
        """Writes the given object to the graph, connected to the given parent.

        For example,

            graph.put_object("me", "feed", message="Hello, world")

        writes "Hello, world" to the active user's wall. Likewise, this
        will comment on a the first post of the active user's feed:

            feed = graph.get_connections("me", "feed")
            post = feed["data"][0]
            graph.put_object(post["id"], "comments", message="First!")

        See http://developers.facebook.com/docs/api#publishing for all of
        the supported writeable objects.

        Most write operations require extended permissions. For example,
        publishing wall posts requires the "publish_stream" permission. See
        http://developers.facebook.com/docs/authentication/ for details about
        extended permissions.
        """
        assert self.access_token, "Write operations require an access token"
        return self.request(parent_object + "/" + connection_name, post_args=data)

    def put_wall_post(self, message, attachment={}, profile_id="me"):
        """Writes a wall post to the given profile's wall.

        We default to writing to the authenticated user's wall if no
        profile_id is specified.

        attachment adds a structured attachment to the status message being
        posted to the Wall. It should be a dictionary of the form:

            {"name": "Link name"
             "link": "http://www.example.com/",
             "caption": "{*actor*} posted a new review",
             "description": "This is a longer description of the attachment",
             "picture": "http://www.example.com/thumbnail.jpg"}

        """
        return self.put_object(profile_id, "feed", message=message, **attachment)

    def put_comment(self, object_id, message):
        """Writes the given comment on the given post."""
        return self.put_object(object_id, "comments", message=message)

    def put_like(self, object_id):
        """Likes the given post."""
        return self.put_object(object_id, "likes")

    def delete_object(self, id):
        """Deletes the object with the given ID from the graph."""
        self.request(id, post_args={"method": "delete"})

    def request(self, path, args=None, post_args=None):
        """Fetches the given path in the Graph API.

        We translate args to a valid query string. If post_args is given,
        we send a POST request to the given path with the given arguments.
        """
        if not args: args = {}
        if self.access_token:
            if post_args is not None:
                post_args["access_token"] = self.access_token
            else:
                args["access_token"] = self.access_token
        post_data = None if post_args is None else urllib.urlencode(post_args)
        file = urllib.urlopen("https://graph.facebook.com/" + path + "?" +
                              urllib.urlencode(args), post_data)
        try:
            response = _parse_json(file.read())
        finally:
            file.close()
        if response.get("error"):
            raise GraphAPIError(response["error"]["type"],
                                response["error"]["message"])
        return response


class GraphAPIError(Exception):
    def __init__(self, type, message):
        Exception.__init__(self, message)
        self.type = type

class FacebookError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

    
    
