from lexer import tokenize
from ast_nodes import Declaration, Assignment, FunctionCall, BinaryOp, Identifier, Literal, Program

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def advance(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, type_):
        tok = self.advance()
        if tok.type != type_:
            raise SyntaxError(f"Expected {type_}, got {tok.type} at line {tok.line}")
        return tok

    def parse_program(self):
        statements = []
        while self.peek() is not None:
            statements.append(self.parse_statement())
        return Program(statements)

    def parse_statement(self):
        tok = self.peek()
        if tok.type == 'KEYWORD' and tok.value in ('int', 'char'):
            return self.parse_declaration()
        if tok.type == 'ID':
            next_tok = self.tokens[self.pos + 1]
            if next_tok.type == 'LPAREN':
                stmt = self.parse_function_call()
                self.expect('SEMI')
                return stmt
            return self.parse_assignment()
        raise SyntaxError(f"Unexpected token {tok.type} at line {tok.line}")

    def parse_declaration(self):
        type_tok = self.advance()
        name_tok = self.expect('ID')
        array_size = None
        if self.peek() and self.peek().type == 'LBRACK':
            self.advance()
            size_tok = self.expect('NUMBER')
            array_size = int(size_tok.value)
            self.expect('RBRACK')
        self.expect('SEMI')
        return Declaration(type_tok.value, name_tok.value, array_size, type_tok.line)

    def parse_assignment(self):
        name_tok = self.expect('ID')
        index = None
        if self.peek() and self.peek().type == 'LBRACK':
            self.advance()
            index = self.parse_expr()
            self.expect('RBRACK')
        self.expect('OP')
        value = self.parse_expr()
        self.expect('SEMI')
        return Assignment(name_tok.value, index, value, name_tok.line)

    def parse_function_call(self):
        name_tok = self.expect('ID')
        self.expect('LPAREN')
        args = []
        while self.peek().type != 'RPAREN':
            args.append(self.parse_expr())
            if self.peek().type == 'COMMA':
                self.advance()
        self.expect('RPAREN')
        return FunctionCall(name_tok.value, args, name_tok.line)

    def parse_expr(self):
        left = self.parse_term()
        while self.peek() and self.peek().type == 'OP' and self.peek().value == '+':
            op = self.advance().value
            right = self.parse_term()
            left = BinaryOp(op, left, right, left.line)
        return left

    def parse_term(self):
        tok = self.peek()
        if tok.type == 'NUMBER':
            self.advance()
            return Literal(int(tok.value), tok.line)
        if tok.type == 'STRING':
            self.advance()
            return Literal(tok.value.strip('"'), tok.line)
        if tok.type == 'ID':
            if self.tokens[self.pos + 1].type == 'LPAREN':
                return self.parse_function_call()
            self.advance()
            return Identifier(tok.value, tok.line)
        raise SyntaxError(f"Unexpected token {tok.type} at line {tok.line}")

if __name__ == "__main__":
    sample = 'char buffer[10];\ngets(buffer);'
    tokens = tokenize(sample)
    ast = Parser(tokens).parse_program()
    for stmt in ast.statements:
        print(stmt)