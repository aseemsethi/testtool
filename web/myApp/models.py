from django.db import models

# Create your models here.
class cfg(models.Model):
	PROTO_CHOICES = ( ('BGP', 'BGP'), ('SSL', 'SSL'), ('SSL_PERF', 'SSL_PERF'), ('OPENVPN', 'OPENVPN'))
	PROTOCOL = ( ('TCP', 'TCP'), ('UDP', 'UDP'))
	serverIP = models.GenericIPAddressField()
	custID = models.IntegerField()
	# SSL
	sslPort = models.IntegerField()
	protocol = models.CharField(
				max_length=8, choices=PROTO_CHOICES, default='BGP',)
	# BGP
	version = models.IntegerField()
	myas = models.IntegerField()
	routerID = models.GenericIPAddressField()
	withdrawnPrefix = models.IntegerField()
	withdrawnRoute = models.GenericIPAddressField()
	pathFlag = models.IntegerField()
	pathType = models.IntegerField()
	pathLen = models.IntegerField()
	pathValue = models.IntegerField()
	pathValueNextHop = models.GenericIPAddressField()
	nlriLen =  models.IntegerField()
	nlriPrefix = models.GenericIPAddressField()
	nlriRepeat = models.IntegerField()
	repeatUpdate = models.IntegerField()
	# OPENVPN
	ovProto = models.CharField(max_length=8, choices=PROTOCOL, default='UDP',)

	slug = models.SlugField(unique=True)
