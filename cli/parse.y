%{
#include <stdio.h>
#include "parse.h"
int yylex(void);
int proto;
%}

%union { char *s; int i; } 
%token PROTOCOL BGP OV SSL SHOW HELP CMD END ERROR NL
%token UPDATE WITHDRAW

%%
config: lines config
		| lines
		;
lines:	expr NL
		| commonCmds NL
		| bgpCmds NL
		| sslCmds NL
		| NL
		;  		
expr:   PROTOCOL BGP     { proto = BGP; printf("Set protocol to BGP\n"); }
		| PROTOCOL SSL   { proto = SSL; printf("Set protocol to SSL\n"); }
		| PROTOCOL ERROR { printf("Set protocol error\n"); }
		;
commonCmds:	SHOW CMD        { printf("...SHOW %s\n", $2.s); }		
		| HELP			{ printf("...HELP\n"); }
		| END			{ printf("...Protocol END\n"); }
		| SHOW HELP		{ printf("...Help Cmds"); }
		| SHOW			{ printf("...Please enter param"); }
		| CMD			{ printf("...Invalid command %s\n", $1.s); }
		;
bgpCmds: UPDATE CMD		{ printf("...update %s\n", $2.s); 
							CLIsendUpdate($2.s);}	
		| WITHDRAW CMD	{ printf("...withdraw %s\n", $2.s); 
							CLIsendWithdraw($2.s);}		
		| UPDATE		{ printf("...Please enter file"); }
		| WITHDRAW		{ printf("...Please enter file"); }
		;
sslCmds: UPDATE CMD		{ printf("...update %s\n", $2.s); }	
		;

%%
void yyerror(char *s)
{
	fprintf(stderr,"%s\n",s);
	return;
}
int cliLoop (void)
{
	int yydebug=1;
	//yyin = fopen(argv[1], "r");
	yyparse();
	//fclose(yyin);
	return 0;
}

