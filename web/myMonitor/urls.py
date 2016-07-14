"""myMonitor URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.conf.urls import url
from django.contrib import admin
from django.views.generic import TemplateView

urlpatterns = [
	url(r'^$', 'myApp.views.index', name ='home'),
	url( r'^about/$', TemplateView.as_view(template_name ='about.html'), name ='about'),
	url( r'^contact/$', TemplateView.as_view(template_name ='contact.html'), name ='contact'),
	url( r'^cfg/(?P<slug>[-\w]+)/$', 'myApp.views.cfg_detail',
			 name='cfg_detail'), 
	url( r'^cfg/(?P<slug>[-\w]+)/(?P<proto>[-\w]+)/edit/$', 'myApp.views.edit_cfg',
			name ='edit_cfg'),
	url( r'^run/(?P<slug>[-\w]+)/(?P<proto>[-\w]+)/$', 'myApp.views.run_cfg',
			name ='run_cfg'),
	url( r'^admin/', include(admin.site.urls)),
]
