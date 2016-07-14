from django.forms import ModelForm
from myApp.models import cfg


class cfgForm(ModelForm):
    class Meta:
        model = cfg
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(cfgForm, self).__init__(*args, **kwargs)
        self.fields['sslPort'].required = False
        self.fields['custID'].required = False
        self.fields['protocol'].required = False
        self.fields['version'].required = False
        self.fields['myas'].required = False
        self.fields['routerID'].required = False
        self.fields['withdrawnPrefix'].required = False
        self.fields['withdrawnRoute'].required = False
        self.fields['pathFlag'].required = False
        self.fields['pathType'].required = False
        self.fields['pathLen'].required = False
        self.fields['pathValue'].required = False
        self.fields['pathValueNextHop'].required = False
        self.fields['nlriLen'].required = False
        self.fields['nlriPrefix'].required = False
        self.fields['nlriRepeat'].required = False
        self.fields['repeatUpdate'].required = False
        self.fields['ovProto'].required = False
        self.fields['slug'].required = False
