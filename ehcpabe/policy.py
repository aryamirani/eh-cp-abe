"""Access trees (paper Sect. III-C).

Every non-leaf node is a k-of-num threshold gate (AND = num-of-num, OR = 1-of-num);
leaves are attributes. A `name` on a non-leaf node binds a piece of data to the
policy of the subtree rooted there -- in Part 1 only the root carries data.

Example (the paper's motivating policy T_B):

    T = And("taskX", Or("TeamA", "TeamB"), name="M")
"""

import itertools

_ids = itertools.count(1)


class Node:
    def __init__(self, k=None, children=(), attr=None, name=None):
        self.uid = next(_ids)
        self.k = k
        self.children = list(children)
        self.attr = attr
        self.name = name
        if self.is_leaf:
            if self.children:
                raise ValueError("leaf nodes have no children")
        elif not 0 < k <= len(self.children):
            raise ValueError(f"threshold must satisfy 0 < k <= num, got k={k}, num={len(self.children)}")

    @property
    def is_leaf(self):
        return self.attr is not None

    def walk(self):
        """Pre-order traversal (top-down)."""
        yield self
        for c in self.children:
            yield from c.walk()

    def internal_nodes(self):
        return [n for n in self.walk() if not n.is_leaf]

    def leaves(self):
        return [n for n in self.walk() if n.is_leaf]

    def find(self, name):
        for n in self.walk():
            if n.name == name:
                return n
        raise KeyError(f"no node named {name!r}")

    def parent_of(self, target):
        for n in self.walk():
            if any(c is target for c in n.children):
                return n
        return None

    def satisfied_by(self, attrs):
        """T_x(gamma) = 1 ?"""
        if self.is_leaf:
            return self.attr in attrs
        return sum(c.satisfied_by(attrs) for c in self.children) >= self.k

    def __repr__(self):
        return to_string(self)


def _coerce(child):
    return Attr(child) if isinstance(child, str) else child


def Attr(attribute):
    return Node(attr=attribute)


def Threshold(k, *children, name=None):
    return Node(k=k, children=[_coerce(c) for c in children], name=name)


def And(*children, name=None):
    return Threshold(len(children), *children, name=name)


def Or(*children, name=None):
    return Threshold(1, *children, name=name)


def to_string(node):
    if node.is_leaf:
        return node.attr
    n = len(node.children)
    gate = "AND" if node.k == n else "OR" if node.k == 1 else f"{node.k}-of-{n}"
    inner = f" {gate} ".join(to_string(c) for c in node.children) if gate in ("AND", "OR") \
        else f"{gate}(" + ", ".join(to_string(c) for c in node.children) + ")"
    body = f"({inner})" if gate in ("AND", "OR") else inner
    return f"{node.name}:{body}" if node.name else body
