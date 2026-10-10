from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Declaration:
    var_type: str
    name: str
    array_size: Optional[int]
    line: int

@dataclass
class Assignment:
    target: str
    index: Optional[object]
    value: object
    line: int

@dataclass
class FunctionCall:
    name: str
    args: List[object]
    line: int

@dataclass
class BinaryOp:
    op: str
    left: object
    right: object
    line: int

@dataclass
class Identifier:
    name: str
    line: int

@dataclass
class Literal:
    value: object
    line: int

@dataclass
class Program:
    statements: List[object]