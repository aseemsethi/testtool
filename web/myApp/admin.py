from django.contrib import admin
from myApp.models import cfg

class cfgAdmin(admin.ModelAdmin):
	model=cfg
	list_display = ('custID', 'serverIP', 'protocol')
	prepoulated_fields = { 'slug':('custID',) }

# Register your models here.
admin.site.register(cfg)
