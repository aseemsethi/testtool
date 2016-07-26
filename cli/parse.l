%{
#include <unistd.h>
#include <string.h>
#include "parse.h"
#include "y.tab.h"
void yyerror(char*);
%}

%START PROTOCOL_s BGP_s OV_s SSL_s

%%
^protocol			{BEGIN PROTOCOL_s; return PROTOCOL;}
<PROTOCOL_s>bgp		{printf("bgp>"); BEGIN BGP_s; return BGP;}
<PROTOCOL_s>openvpn	{printf("openvpn>"); BEGIN OV_s; return OV;}
<PROTOCOL_s>ssl		{printf("ssl>"); BEGIN SSL_s; return SSL;}
<PROTOCOL_s>[A-Za-z0-9]+	{printf("error!"); BEGIN 0; return ERROR;}
<BGP_s,SSL_s>show	{return SHOW;}
<BGP_s>update		{return UPDATE;}
<BGP_s>withdraw		{return WITHDRAW;}
<BGP_s>help			{printf("bgp>"); return HELP;}
<BGP_s>end			{printf("proto>"); BEGIN 0; return END;}
<BGP_s,SSL_s>[A-Za-z0-9]+	{yylval.s = strdup(yytext); return CMD;}
<BGP_s>\n			{printf("bgp>"); return NL;}
<SSL_s>\n			{printf("ssl>"); return NL;}
<OV_s>\n			{printf("ov>"); return NL;}
\n					{printf("select>"); return NL;}
[A-Za-z0-9]+		;
[ \t]				;
[\?]				return HELP;
%%

int yywrap() {
	printf("\n yywrap called");
	return 1;
}
