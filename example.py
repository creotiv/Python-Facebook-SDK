from facebook import Facebook

print "Using App Token\n\n"
fb = Facebook({},'app_id','app_secret')
session  = fb.getSession()
graph    = fb.getGraph()
user     = graph.get_object("100002026707702")
friends  = graph.get_connections(user["id"], "friends")
print friends

print "Using Signed Request\n\n"
fb = Facebook({'signed_request':'...'},'app_id','app_secret')
session  = fb.getSession()
graph    = fb.getGraph()
user     = graph.get_object("me")
friends  = graph.get_connections(user["id"], "friends")
print friends

print "Using User Cookie\n\n"
fb = Facebook({'fbsr_app_id':'...'},'app_id','app_secret')
session  = fb.getSession()
graph    = fb.getGraph()
user     = graph.get_object("me")
friends  = graph.get_connections(user["id"], "friends")
print friends

