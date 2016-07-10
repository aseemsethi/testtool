%{
#include <unistd.h>
#include <string.h>
#include "parse.h"
#include "y.tab.h"
void yyerror(char*);
%}

%START PROTOCOL_s BGP_s OV_s

%%
^protocol			{BEGIN PROTOCOL_s; return PROTOCOL;}
<PROTOCOL_s>bgp		{printf("bgp>"); BEGIN BGP_s; return BGP;}
<PROTOCOL_s>openvpn	{printf("openvpn>"); BEGIN OV_s; return OV;}
<PROTOCOL_s>[A-Za-z0-9]+	{printf("error!"); BEGIN 0; return ERROR;}
<BGP_s>show			{return SHOW;}
<BGP_s>help			{printf("bgp>"); return HELP;}
<BGP_s>end			{printf("proto>"); BEGIN 0; return END;}
<BGP_s>[A-Za-z0-9]+	{yylval.s = strdup(yytext); return CMD;}
<BGP_s>\n			{printf("bgp>"); return NL;}
\n					{printf("proto>"); return NL;}
[A-Za-z0-9]+		;
[ \t]				;
[\?]				return HELP;
%%

int yywrap() {
	printf("\n yywrap called");
	return 1;
}
