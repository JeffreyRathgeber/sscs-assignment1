"""Print Halstead metrics for Python files: python halstead.py FILE [FILE...]"""

import keyword
import math
import sys
import tokenize

LITERALS = {"True", "False", "None"}
OPERAND_TOKENS = {tokenize.NUMBER, tokenize.STRING, tokenize.FSTRING_MIDDLE}


def halstead(path: str) -> None:
    operators: list[str] = []
    operands: list[str] = []
    with tokenize.open(path) as f:
        for tok in tokenize.generate_tokens(f.readline):
            s = tok.string
            if tok.type == tokenize.OP and s not in ")]}":  # count a bracket pair once
                operators.append(s)
            elif tok.type == tokenize.NAME and keyword.iskeyword(s) and s not in LITERALS:
                operators.append(s)
            elif tok.type == tokenize.NAME or tok.type in OPERAND_TOKENS:
                operands.append(s)

    n1, n2 = len(set(operators)), len(set(operands))
    big_n1, big_n2 = len(operators), len(operands)
    volume = (big_n1 + big_n2) * math.log2(n1 + n2)
    difficulty = (n1 / 2) * (big_n2 / n2)

    print(f"== {path} ==")
    print(f"n1={n1} n2={n2} N1={big_n1} N2={big_n2}")
    print(f"vocabulary={n1 + n2} length={big_n1 + big_n2}")
    print(f"volume={volume:.2f} difficulty={difficulty:.2f} effort={difficulty * volume:.2f}")


if __name__ == "__main__":
    for file in sys.argv[1:]:
        halstead(file)
