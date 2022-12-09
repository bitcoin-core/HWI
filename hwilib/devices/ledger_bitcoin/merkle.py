from typing import List, Iterable, Mapping

from ...common import sha256
from ..._serialize import ser_compact_size as write_varint

NIL = bytes([0] * 32)


def floor_lg(n: int) -> int:
    """Return floor(log_2(n)) for a positive integer `n`"""

    assert n > 0

    r = 0
    t = 1
    while 2 * t <= n:
        t = 2 * t
        r = r + 1
    return r


def ceil_lg(n: int) -> int:
    """Return ceiling(log_2(n)) for a positive integer `n`."""

    assert n > 0

    r = 0
    t = 1
    while t < n:
        t = 2 * t
        r = r + 1
    return r


def is_power_of_2(n: int) -> bool:
    """For a positive integer `n`, returns `True` is `n` is a perfect power of 2, `False` otherwise."""

    assert n >= 1

    return n & (n - 1) == 0


def largest_power_of_2_less_than(n: int) -> int:
    """For an integer `n` which is at least 2, returns the largest exact power of 2 that is strictly less than `n`."""

    assert n > 1

    if is_power_of_2(n):
        return n // 2
    else:
        return 1 << floor_lg(n)


def element_hash(element_preimage: bytes) -> bytes:
    """Computes the hash of an element to be stored in the Merkle tree."""

    return sha256(b'\x00' + element_preimage)


def combine_hashes(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("The elements must be 32-bytes sha256 outputs.")

    return sha256(b'\x01' + left + right)


# root is the only node with parent == None
# leaves have left == right == None
class Node:
    def __init__(self, left, right, parent, value: bytes):
        self.left = left
        self.right = right
        self.parent = parent
        self.value = value

    def recompute_value(self):
        assert self.left is not None
        assert self.right is not None
        self.value = combine_hashes(self.left.value, self.right.value)

    def sibling(self):
        if self.parent is None:
            raise IndexError("The root does not have a sibling.")

        if self.parent.left == self:
            return self.parent.right
        elif self.parent.right == self:
            return self.parent.left
        else:
            raise IndexError("Invalid state: not a child of his parent.")


def make_tree(leaves: List[Node], begin: int, size: int) -> Node:
    """Given a list of nodes, builds the left-complete Merkle tree on top of it.
    The nodes in `leaves` are modified by setting their `parent` field appropriately.
    It returns the root of the newly built tree.
    """

    if size == 0:
        return []
    if size == 1:
        return leaves[begin]

    lchild_size = largest_power_of_2_less_than(size)

    lchild = make_tree(leaves, begin, lchild_size)
    rchild = make_tree(leaves, begin + lchild_size, size - lchild_size)
    root = Node(lchild, rchild, None, None)
    root.recompute_value()
    lchild.parent = rchild.parent = root
    return root


class MerkleTree:
    """
    Maintains a dynamic vector of values and the Merkle tree built on top of it. The elements of the vector are stored
    as the leaves of a binary tree. It is possible to add a new element to the vector, or change an existing element;
    the hashes in the Merkle tree will be recomputed after each operation in O(log n) time, for a vector with n
    elements.
    The value of each internal node is the hash of the concatenation of:
    - a single byte 0x01;
    - the values of the left child;
    - the value of the right child.

    The binary tree has the following properties (assuming the vector contains n leaves):
    - There are always n - 1 internal nodes; all the internal nodes have exactly two children.
    - If a subtree has n > 1 leaves, then the left subchild is a complete subtree with p leaves, where p is the largest
      power of 2 smaller than n.
    """

    def __init__(self, elements: Iterable[bytes] = []):
        self.leaves = [Node(None, None, None, el) for el in elements]
        n_elements = len(self.leaves)
        if n_elements > 0:
            self.root_node = make_tree(self.leaves, 0, n_elements)
            self.depth = ceil_lg(n_elements)
        else:
            self.root_node = None
            self.depth = None

    def __len__(self) -> int:
        """Return the total number of leaves in the tree."""
        return len(self.leaves)

    @property
    def root(self) -> bytes:
        """Return the Merkle root, or None if the tree is empty."""
        return NIL if self.root_node is None else self.root_node.value

    def copy(self):
        """Return an identical copy of this Merkle tree."""
        return MerkleTree([leaf.value for leaf in self.leaves])

    def add(self, x: bytes) -> None:
        """Add an element as new leaf, and recompute the tree accordingly. Cost O(log n)."""

        if len(x) != 32:
            raise ValueError("Inserted elements must be exactly 32 bytes long")

        new_leaf = Node(None, None, None, x)
        self.leaves.append(new_leaf)
        if len(self.leaves) == 1:
            self.root_node = new_leaf
            self.depth = 0
            return

        # add a new leaf
        if self.depth == 0:
            ltree_size = 0
        else:
            # number of leaves of the left subtree of cur_root
            ltree_size = 1 << (self.depth - 1)

        cur_root = self.root_node
        cur_root_size = len(self.leaves) - 1

        while not is_power_of_2(cur_root_size):
            cur_root = cur_root.right
            cur_root_size -= ltree_size
            ltree_size /= 2

        # node value will be computed later
        new_node = Node(cur_root, new_leaf, cur_root.parent, None)
        if cur_root.parent is None:
            # replacing the root
            self.depth += 1
            self.root_node = new_node
        else:
            assert cur_root.parent.right == cur_root
            cur_root.parent.right = new_node
        cur_root.parent = new_node
        new_leaf.parent = new_node

        self.fix_up(new_node)

    def set(self, index: int, x: bytes) -> None:
        """
        Set the value of the leaf at position `index` to `x`, recomputing the tree accordingly.
        If `index` equals the current number of leaves, then it is equivalent to `add(x)`.

        Cost: Worst case O(log n).
        """
        assert 0 <= index <= len(self.leaves)

        if not (0 <= index <= len(self.leaves)):
            raise ValueError(
                "The index must be at least 0, and at most the current number of leaves.")

        if len(x) != 32:
            raise ValueError("Inserted elements must be exactly 32 bytes long.")

        if index == len(self.leaves):
            self.add(x)
        else:
            self.leaves[index].value = x
            self.fix_up(self.leaves[index].parent)

    def fix_up(self, node: Node):
        while node is not None:
            node.recompute_value()
            node = node.parent

    def get(self, i: int) -> bytes:
        """Return the value of the leaf with index `i`, where 0 <= i < len(self)."""
        return self.leaves[i].value

    def leaf_index(self, x: bytes) -> int:
        """Return the index of the leaf with hash `x`. Raises `ValueError` if not found."""
        idx = 0
        while idx < len(self):
            if self.leaves[idx].value == x:
                return idx
            idx += 1
        raise ValueError("Leaf not found")

    def prove_leaf(self, index: int) -> List[bytes]:
        """Produce the Merkle proof of membership for the leaf with the given index where 0 <= index < len(self)."""
        node = self.leaves[index]
        proof = []
        while node.parent is not None:
            sibling = node.sibling()
            assert sibling is not None

            proof.append(sibling.value)

            node = node.parent

        return proof


def get_merkleized_map_commitment(mapping: Mapping[bytes, bytes]) -> bytes:
    """Returns a serialized Merkleized map commitment, encoded as the concatenation of:
       - the number of key/value pairs, as a Bitcoin-style varint;
       - the root of the Merkle tree of the keys
       - the root of the Merkle tree of the values.
    """

    items_sorted = list(sorted(mapping.items()))
    keys_hashes = [element_hash(i[0]) for i in items_sorted]
    values_hashes = [element_hash(i[1]) for i in items_sorted]
    return write_varint(len(mapping)) + MerkleTree(keys_hashes).root + MerkleTree(values_hashes).root
