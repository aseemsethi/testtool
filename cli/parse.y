%{
#include <stdio.h>
#include "parse.h"
int yylex(void);
%}

%union { char *s; int i; } 
%token PROTOCOL BGP OV SHOW HELP CMD END ERROR NL
%token UPDATE WITHDRAW

%%
config: lines config
		| lines
		;
lines:	expr NL
		| cmds NL
		| bgpCmds NL
		| NL
		;  		
expr:   PROTOCOL BGP     { printf("Set protocol to BGP\n"); }
		| PROTOCOL ERROR   { printf("Set protocol error\n"); }
		;
cmds:	SHOW CMD        { printf("...SHOW %s\n", $2.s); }		
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

