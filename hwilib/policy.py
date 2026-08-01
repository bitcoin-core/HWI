"""BIP388 wallet policy helpers."""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Set, Tuple

from .descriptor import DescriptorChecksum
from .errors import BadArgumentError
from .key import ExtendedKey, KeyOriginInfo


_EXTENDED_KEY_RE = re.compile(
    r"(?P<origin>\[[^\]]+\])?(?P<key>[1-9A-HJ-NP-Za-km-z]{100,120})"
)
_PLACEHOLDER_RE = re.compile(r"@(0|[1-9][0-9]*)")
_MUSIG_RE = re.compile(r"(?<![A-Za-z0-9_])musig\(")


@dataclass
class BIP388Policy:
    """A serialization-agnostic BIP388 policy."""

    name: str
    descriptor_template: str
    keys_info: List[str]
    registration: Optional[str] = None

    @classmethod
    def from_descriptor(
        cls,
        name: str,
        descriptor: str,
        registration: Optional[str] = None,
    ) -> "BIP388Policy":
        """Convert a combined multipath output descriptor into a BIP388 policy."""

        descriptor = _strip_and_check_checksum(descriptor)
        if any(char.isspace() for char in descriptor):
            raise BadArgumentError("Whitespace is not allowed in a BIP388 descriptor")
        _check_balanced(descriptor)

        keys_info: List[str] = []
        key_indexes: Dict[str, int] = {}
        xpub_origins: Dict[str, str] = {}
        template_parts: List[str] = []
        last_end = 0

        for match in _EXTENDED_KEY_RE.finditer(descriptor):
            key_str = match.group("key")
            try:
                extkey = ExtendedKey.deserialize(key_str)
            except Exception as exc:
                raise BadArgumentError(f"Invalid extended key in descriptor: {key_str}") from exc
            if extkey.is_private:
                raise BadArgumentError("BIP388 key information must use extended public keys")

            origin_str = ""
            raw_origin = match.group("origin")
            if raw_origin is not None:
                try:
                    origin = KeyOriginInfo.from_string(raw_origin[1:-1])
                except Exception as exc:
                    raise BadArgumentError(f"Invalid key origin: {raw_origin}") from exc
                normalized_origin = origin.to_string(hardened_char="'")
                origin_str = f"[{normalized_origin}]"
            elif match.start("key") > 0 and descriptor[match.start("key") - 1] == "]":
                raise BadArgumentError("Invalid key origin in descriptor")

            canonical_xpub = extkey.to_string()
            key_info = origin_str + canonical_xpub
            previous_key_info = xpub_origins.setdefault(canonical_xpub, key_info)
            if previous_key_info != key_info:
                raise BadArgumentError("The same extended public key has conflicting origins")

            if key_info not in key_indexes:
                key_indexes[key_info] = len(keys_info)
                keys_info.append(key_info)

            template_parts.append(descriptor[last_end:match.start()])
            template_parts.append(f"@{key_indexes[key_info]}")
            last_end = match.end()

        if not keys_info:
            raise BadArgumentError("Descriptor does not contain any extended public keys")

        template_parts.append(descriptor[last_end:])
        descriptor_template = "".join(template_parts).replace("/<0;1>/*", "/**")
        _validate_template(descriptor_template, len(keys_info))

        return cls(
            name=name,
            descriptor_template=descriptor_template,
            keys_info=keys_info,
            registration=registration,
        )


def _strip_and_check_checksum(descriptor: str) -> str:
    if descriptor.count("#") > 1:
        raise BadArgumentError("Descriptor has more than one checksum separator")
    if "#" not in descriptor:
        return descriptor

    descriptor, checksum = descriptor.split("#", 1)
    expected = DescriptorChecksum(descriptor)
    if checksum != expected:
        raise BadArgumentError(
            f"The descriptor checksum does not match: got {checksum}, expected {expected}"
        )
    return descriptor


def _check_balanced(descriptor: str) -> None:
    pairs = {")": "(", "}": "{"}
    stack: List[str] = []
    for char in descriptor:
        if char in "({":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                raise BadArgumentError("Descriptor has unbalanced delimiters")
    if stack:
        raise BadArgumentError("Descriptor has unbalanced delimiters")


def _find_closing_parenthesis(template: str, open_pos: int) -> int:
    depth = 1
    for pos in range(open_pos + 1, len(template)):
        if template[pos] == "(":
            depth += 1
        elif template[pos] == ")":
            depth -= 1
            if depth == 0:
                return pos
    raise BadArgumentError("Descriptor has an unterminated musig expression")


def _parse_derivation(template: str, pos: int) -> Tuple[int, Set[int]]:
    if template.startswith("/**", pos):
        return pos + 3, {0, 1}

    match = re.match(r"/<(0|[1-9][0-9]*);(0|[1-9][0-9]*)>/\*", template[pos:])
    if match is None:
        raise BadArgumentError(
            "Every BIP388 key placeholder must use /** or /<NUM;NUM>/*"
        )
    first = int(match.group(1))
    second = int(match.group(2))
    if first == second or first >= (1 << 31) or second >= (1 << 31):
        raise BadArgumentError("Invalid BIP388 receive/change derivation")
    return pos + match.end(), {first, second}


def _validate_template(template: str, key_count: int) -> None:
    if "[" in template or "]" in template:
        raise BadArgumentError("Descriptor contains key origin data without an extended key")
    if _EXTENDED_KEY_RE.search(template) is not None:
        raise BadArgumentError("A BIP388 descriptor template may only contain key placeholders")

    musig_placeholder_spans: List[Tuple[int, int]] = []
    usages: Dict[Tuple[str, Tuple[int, ...]], List[Set[int]]] = {}
    for match in _MUSIG_RE.finditer(template):
        close_pos = _find_closing_parenthesis(template, match.end() - 1)
        args = template[match.end():close_pos]
        if re.fullmatch(r"@[0-9]+(?:,@[0-9]+)+", args) is None:
            raise BadArgumentError("A BIP388 musig expression must contain only key placeholders")
        indexes = tuple(int(value) for value in re.findall(r"@([0-9]+)", args))
        if len(set(indexes)) != len(indexes):
            raise BadArgumentError("A BIP388 musig expression cannot repeat a key")
        _, branches = _parse_derivation(template, close_pos + 1)
        identity = ("musig", tuple(sorted(indexes)))
        usages.setdefault(identity, []).append(branches)
        musig_placeholder_spans.append((match.end(), close_pos))

    def in_musig(pos: int) -> bool:
        return any(start <= pos < end for start, end in musig_placeholder_spans)

    seen: Set[int] = set()
    next_index = 0
    for match in _PLACEHOLDER_RE.finditer(template):
        index = int(match.group(1))
        if index >= key_count:
            raise BadArgumentError(f"BIP388 placeholder @{index} has no corresponding key")
        if index not in seen:
            if index != next_index:
                raise BadArgumentError("BIP388 keys are not ordered by first placeholder use")
            seen.add(index)
            next_index += 1
        if not in_musig(match.start()):
            _, branches = _parse_derivation(template, match.end())
            usages.setdefault(("key", (index,)), []).append(branches)

    if seen != set(range(key_count)):
        raise BadArgumentError("Not every BIP388 key is used by the descriptor template")

    for branch_sets in usages.values():
        used: Set[int] = set()
        for branches in branch_sets:
            if used.intersection(branches):
                raise BadArgumentError("A BIP388 key is reused in overlapping derivation branches")
            used.update(branches)
