import re
from collections import namedtuple

Token = namedtuple("Token", ["type", "value", "line"])

TOKEN_SPEC = [
    ("NUMBER",    r'\d+'),
    ("STRING",    r'"[^"]*"'),
    ("CHAR",      r"'[^']*'"),
    ("ID",        r'[A-Za-z_][A-Za-z0-9_]*'),
    ("OP",        r'==|!=|<=|>=|[+\-*/=<>]'),
    ("LBRACK",    r'\['),
    ("RBRACK",    r'\]'),
    ("LPAREN",    r'\('),
    ("RPAREN",    r'\)'),
    ("LBRACE",    r'\{'),
    ("RBRACE",    r'\}'),
    ("SEMI",      r';'),
    ("COMMA",     r','),
    ("NEWLINE",   r'\n'),
    ("SKIP",      r'[ \t]+'),
    ("MISMATCH",  r'.'),
]

KEYWORDS = {"int", "char", "if", "while", "return"}

def tokenize(code):
    tokens = []
    line_num = 1
    regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in TOKEN_SPEC)
    for match in re.finditer(regex, code):
        kind = match.lastgroup
        value = match.group()
        if kind == 'NEWLINE':
            line_num += 1
            continue
        if kind == 'SKIP':
            continue
        if kind == 'ID' and value in KEYWORDS:
            kind = 'KEYWORD'
        if kind == 'MISMATCH':
            raise SyntaxError(f"Unexpected character {value!r} at line {line_num}")
        tokens.append(Token(kind, value, line_num))
    return tokens

if __name__ == "__main__":
    sample = 'char buffer[10];\ngets(buffer);'
    for tok in tokenize(sample):
        print(tok)