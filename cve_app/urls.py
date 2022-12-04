from django.urls import path
from .views import *

urlpatterns = [
    path('', Home.as_view()),
    path('signup', signup_here, name="sign"),
    path('verify', verify_email),
    path('login', login),
    path('get_cves', cve_finder),
    path('logout', logout)
]
