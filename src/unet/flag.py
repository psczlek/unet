"""
Command-line flag parsing.
"""


from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn, override

from unet.coloring import RGB, Color, Hex, supports_colors, supports_true_color

__all__ = [
    "FlagParser",
    "FlagHelpFormatter",
    "FlagHelpFormatterColor",
    "PositionalFlag",
    "OptionFlag",
    "Group",
]


@dataclass(frozen=True, kw_only=True)
class PositionalFlag:
    help: str = "this option lacks documentation"
    nargs: int | str | None = None
    type: argparse.FileType | Callable[[str], Any] | None = None
    default: Any | None = None


@dataclass(frozen=True, kw_only=True)
class OptionFlag:
    short: str | None = None
    long: str | None = None
    action: str | type[argparse.Action] | None = None
    nargs: int | str | None = None
    const: Any | None = None
    help: str = "this option lacks documentation"
    type: argparse.FileType | Callable[[str], Any] | None = None
    required: bool | None = None
    default: Any | None = None
    choices: Iterable[Any] | None = None
    metavar: str | tuple[str, ...] | None = None
    version: str | None = None


@dataclass(frozen=True, kw_only=True)
class Group:
    description: str | None = None
    arguments: dict[str, PositionalFlag | OptionFlag | Group]


def _get_default_color(k: str) -> str | RGB | Hex | None:
    default_colors: dict[str, tuple[str | None, str | RGB | Hex | None]] = {
        "usage_prefix": ("green bold", RGB(4, 165, 229, bold=True)),
        "usage_prog": ("green", RGB(125, 199, 230)),
        "description": ("yellow", RGB(255, 245, 160)),
        "section": ("green bold", RGB(4, 165, 229, bold=True)),
        "flag": ("cyan", RGB(40, 178, 203)),
        "metavar": (None, RGB(253, 157, 99)),
        "help": (None, None),
    }

    try:
        if supports_true_color():
            color = default_colors[k][1]
        elif supports_colors():
            color = default_colors[k][0]
        else:
            color = None
        return color
    except KeyError:
        return None


@dataclass(frozen=True, kw_only=True)
class FlagHelpFormatterColor:
    usage_prefix: str | RGB | Hex | None = _get_default_color("usage_prefix")
    usage_prog: str | RGB | Hex | None = _get_default_color("usage_prog")
    description: str | RGB | Hex | None = _get_default_color("description")
    section: str | RGB | Hex | None = _get_default_color("section")
    flag: str | RGB | Hex | None = _get_default_color("flag")
    metavar: str | RGB | Hex | None = _get_default_color("metavar")
    help: str | RGB | Hex | None = _get_default_color("help")


class FlagHelpFormatter(argparse.HelpFormatter):
    """
    Same as `argparse.HelpFormatter`, but output can be colorified.
    """

    def __init__(
            self,
            prog: str,
            indent_increment: int = 2,
            max_help_position: int = 56,
            width: int = 100,
            color: FlagHelpFormatterColor | None = None,
            colorify: bool = True
    ) -> None:
        self._colorify = colorify
        if self._colorify:
            if color is not None:
                self._color = color
            else:
                self._color = FlagHelpFormatterColor()

        super().__init__(prog, indent_increment, max_help_position, width)

    # the functions below are just copy and paste lines from the argparse
    # module with minor changes that make the output colored. I've also changed
    # apostrophes to quotation marks

    @override
    def _format_usage(
            self,
            usage: str | None,
            actions: Iterable[argparse.Action],
            groups: Any,
            prefix: str | None,
    ) -> str:
        if prefix is None:
            prefix = "usage: "

        # if usage is specified, use that
        if usage is not None:
            usage = usage % dict(prog=self._prog)

        # if no optionals or positionals are available, usage is just prog
        elif usage is None and not actions:
            usage = "%(prog)s" % dict(prog=self._prog)

        # if optionals and positionals are available, calculate usage
        elif usage is None:
            prog = "%(prog)s" % dict(prog=self._prog)
            # split optionals from positionals
            optionals = []
            positionals = []

            for action in actions:
                if action.option_strings:
                    optionals.append(action)
                else:
                    positionals.append(action)

            # build full usage string
            format = self._format_actions_usage
            action_usage = format(optionals + positionals, groups)
            usage = " ".join([s for s in [prog, action_usage] if s])
            # wrap the usage parts if it's too long
            text_width = self._width - self._current_indent

            if len(prefix) + len(usage) > text_width:
                # break usage into wrappable parts
                part_regexp = (
                    r"\(.*?\)+(?=\s|$)|"
                    r"\[.*?\]+(?=\s|$)|"
                    r"\S+"
                )

                opt_usage = format(optionals, groups)
                pos_usage = format(positionals, groups)
                opt_parts = re.findall(part_regexp, opt_usage)
                pos_parts = re.findall(part_regexp, pos_usage)

                assert " ".join(opt_parts) == opt_usage
                assert " ".join(pos_parts) == pos_usage

                # helper for wrapping lines
                def get_lines(
                        parts: list[str],
                        indent: str,
                        prefix: str | None = None,
                ) -> list[str]:
                    lines: list[str] = []
                    line: list[str] = []
                    indent_length = len(indent)

                    if prefix is not None:
                        line_len = len(prefix) - 1
                    else:
                        line_len = indent_length - 1

                    for part in parts:
                        if line_len + 1 + len(part) > text_width and line:
                            lines.append(indent + " ".join(line))
                            line = []
                            line_len = indent_length - 1
                        line.append(part)
                        line_len += len(part) + 1

                    if line:
                        lines.append(indent + " ".join(line))

                    if prefix is not None:
                        lines[0] = lines[0][indent_length:]

                    return lines

                # if prog is short, follow it with optionals or positionals
                if len(prefix) + len(prog) <= 0.75 * text_width:
                    indent = " " * (len(prefix) + len(prog) + 1)

                    if self._colorify:
                        prog = Color.color(prog, self._color.usage_prog)

                    if opt_parts:
                        lines = get_lines([prog] + opt_parts, indent, prefix)
                        lines.extend(get_lines(pos_parts, indent))
                    elif pos_parts:
                        lines = get_lines([prog] + pos_parts, indent, prefix)
                    else:
                        lines = [prog]
                # if prog is long, put it on its own line
                else:
                    indent = " " * len(prefix)
                    parts = opt_parts + pos_parts
                    lines = get_lines(parts, indent)

                    if len(lines) > 1:
                        lines = []
                        lines.extend(get_lines(opt_parts, indent))
                        lines.extend(get_lines(pos_parts, indent))

                    if self._colorify:
                        prog = Color.color(prog, self._color.usage_prog)

                    lines = [prog] + lines

                # join lines into usage
                usage = "\n".join(lines)

        if self._colorify and prefix == "usage: ":
            prefix = "usage"
            prefix = Color.color(prefix, self._color.usage_prefix)
            prefix += ": "
        elif self._colorify and prefix != "usage:":
            prefix = Color.color(prefix, self._color.usage_prefix)

        return "%s%s\n\n" % (prefix, usage)

    @override
    def _format_actions_usage(
            self,
            actions: Iterable[argparse.Action],
            groups: Any,     # I have no idea how to type hint this one
    ) -> str:
        # find group indices and identify actions in groups
        group_actions = set()
        inserts = {}

        for group in groups:
            if not group._group_actions:
                raise ValueError(f"empty group {group}")

            try:
                start = actions.index(group._group_actions[0])
            except ValueError:
                continue
            else:
                group_action_count = len(group._group_actions)
                end = start + group_action_count

                if actions[start:end] == group._group_actions:
                    suppressed_actions_count = 0

                    for action in group._group_actions:
                        group_actions.add(action)

                        if action.help is argparse.SUPPRESS:
                            suppressed_actions_count += 1

                    exposed_actions_count = group_action_count - suppressed_actions_count

                    if not exposed_actions_count:
                        continue

                    if not group.required:
                        if start in inserts:
                            inserts[start] += " ["
                        else:
                            inserts[start] = "["

                        if end in inserts:
                            inserts[end] += "]"
                        else:
                            inserts[end] = "]"
                    elif exposed_actions_count > 1:
                        if start in inserts:
                            inserts[start] += " ("
                        else:
                            inserts[start] = "("

                        if end in inserts:
                            inserts[end] += ")"
                        else:
                            inserts[end] = ")"

                    for i in range(start + 1, end):
                        inserts[i] = "|"

        # collect all actions format strings
        parts: list[str | None] = []

        for i, action in enumerate(actions):
            # suppressed arguments are marked with None
            # remove | separators for suppressed arguments
            if action.help is argparse.SUPPRESS:
                parts.append(None)

                if inserts.get(i) == "|":
                    inserts.pop(i)
                elif inserts.get(i + 1) == "|":
                    inserts.pop(i + 1)

            # produce all arg strings
            elif not action.option_strings:
                default = self._get_default_metavar_for_positional(action)
                part = self._format_args(action, default)
                # if it's in a group, strip the outer []

                if action in group_actions:
                    if part[0] == "[" and part[-1] == "]":
                        part = part[1:-1]

                # add the action string to the list
                parts.append(part)

            # produce the first way to invoke the option in brackets
            else:
                option_string = action.option_strings[0]

                # if the Optional doesn't take a value, format is:
                #    -s or --long
                if action.nargs == 0:
                    part = action.format_usage()

                # if the Optional takes a value, format is:
                #    -s ARGS or --long ARGS
                else:
                    default = self._get_default_metavar_for_optional(action)
                    args_string = self._format_args(action, default)
                    part = "%s %s" % (option_string, args_string)

                # make it look optional if it's not required or in a group
                if not action.required and action not in group_actions:
                    part = "[%s]" % part

                # add the action string to the list
                parts.append(part)

        # insert things at the necessary indices
        for i in sorted(inserts, reverse=True):
            parts[i:i] = [inserts[i]]

        if self._colorify:
            args = []
            for part in parts:
                if part is not None:
                    # positional argument
                    if "[" not in part and "]" not in part:
                        arg = Color.color(part, self._color.flag)
                        args.append(arg)
                    else:
                        part = part.strip("[]").split(" ")
                        # option and no metavar
                        if len(part) == 1:
                            arg = f"[{Color.color(part[0], self._color.flag)}]"
                            args.append(arg)
                        # option and metavar
                        elif len(part) == 2:
                            arg = Color.color(part[0], self._color.flag)
                            metavar = part[1]
                            metavar = Color.color(metavar, self._color.metavar)
                            arg = "[%s %s]" % (arg, metavar)
                            args.append(arg)
                        # option and metavar has been splitted into parts
                        elif len(part) > 2:
                            arg = Color.color(part[0], self._color.flag)
                            metavar = " ".join(part[1:])
                            metavar = Color.color(metavar, self._color.metavar)
                            arg = "[%s %s]" % (arg, metavar)
                            args.append(arg)

            # don't need the previous parts
            parts.clear()
            parts = args

        # join all the action items with spaces
        text = " ".join([item for item in parts if item is not None])
        # clean up separators for mutually exclusive groups
        open = r"[\[(]"
        close = r"[\])]"
        text = re.sub(r"(%s) " % open, r"\1", text)
        text = re.sub(r" (%s)" % close, r"\1", text)
        text = re.sub(r"%s *%s" % (open, close), r"", text)
        text = text.strip()

        # return the text
        return text

    @override
    def start_section(self, heading: str | None) -> None:
        if self._colorify and heading is not None:
            heading = Color.color(heading, self._color.section)

        super().start_section(heading)

    @override
    def _format_text(self, text: str) -> str:
        if "%(prog)" in text:
            # I assume that's how it's supposed to be. The previous line,
            # `text = text % dict(prog=self._prog)`, was throwing a
            # ValueError. Now it should be fine
            text = text.replace("%(prog)", self._prog)

        text_width = max(self._width - self._current_indent, 11)
        indent = " " * self._current_indent
        filled_text = self._fill_text(text, text_width, indent)

        if self._colorify:
            filled_text = Color.color(filled_text, self._color.description)

        return filled_text + "\n\n"

    @override
    def _format_action(self, action: argparse.Action) -> str:
        # determine the required width and the entry label
        help_position = min(self._action_max_length + 2, self._max_help_position)
        help_width = max(self._width - help_position, 11)
        action_width = help_position - self._current_indent - 2
        action_header = self._format_action_invocation(action)

        # no help; start on same line and add a final newline
        if not action.help:
            action_header = f"{'':>{self._current_indent}}{action_header}"
        # short action name; start on the same line and pad two spaces
        elif len(action_header) <= action_width:
            action_header = (f"{'':>{self._current_indent}}"
                             f"{action_header:<{action_width}}  ")
            indent_first = 0
        else:
            action_header = f"{action_header:>{self._current_indent}}\n"
            indent_first = help_position

        if self._colorify:
            if action_header[:2] == "  ":
                action_header_parts = action_header.split(" ")[2:]
            else:
                action_header_parts = action_header.split(" ")

            indent = 0
            elements = 0

            for element in action_header_parts:
                if not len(element):
                    indent += 1
                else:
                    elements += 1

            action_header_parts = action_header_parts[0:elements]
            result = []

            for element in action_header_parts:
                # short flag
                if element[0] == "-" and element[1] != "-":
                    if "," not in element:
                        element = Color.color(element, self._color.flag)
                        result.append(element)
                    else:
                        element = Color.color(element.strip(","),
                                              self._color.flag)
                        result.append(element + ",")
                # long flag
                elif element[:1] == "--":
                    element = Color.color(element, self._color.flag)
                    result.append(element)
                # metavar
                #
                # a new line can be added because of 'max_help_position',
                # we don't need that so strip it
                elif (element.strip("\n").startswith("<")
                        or element.strip("\n").endswith(">")):
                    if element.endswith("\n"):
                        element = element.strip("\n")
                        element = Color.color(element, self._color.metavar)
                        element += "\n"
                        result.append(element)
                    else:
                        element = Color.color(element, self._color.metavar)
                        result.append(element)
                # positional
                else:
                    element = Color.color(element, self._color.flag)
                    result.append(element)

            action_header = "%*s%s%*s" % (2, "", " ".join(result), indent, "")

        # collect the pieces of the action help
        parts = [action_header]

        # if there was help for the action, add lines of help text
        if action.help and action.help.strip():
            help_text = self._expand_help(action)

            if help_text:
                help_lines = self._split_lines(help_text, help_width)
                parts.append(f"{'':>{indent_first}}{help_lines[0]}\n")

                for line in help_lines[1:]:
                    parts.append(f"{'':>{help_position}}{line}\n")
        # or add a newline if the description doesn't end with one
        elif not action_header.endswith("\n"):
            parts.append("\n")

        # if there are any sub-actions, add their help as well
        for subaction in self._iter_indented_subactions(action):
            parts.append(self._format_action(subaction))

        # return a single string
        return "".join([part for part in parts
                        if part and part is not argparse.SUPPRESS])

    @override
    def _format_action_invocation(self, action: argparse.Action) -> str:
        # positional
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            metavar, = self._metavar_formatter(action, default)(1)

            return metavar
        else:
            parts: list[str] = []

            # optional with no arguments
            if action.nargs == 0:
                option_strings = action.option_strings
                parts.extend(option_strings)
            # optional with a value
            else:
                default = f"<{self._get_default_metavar_for_optional(action)}>"
                args_string = self._format_args(action, default)

                for option_string in action.option_strings:
                    # add metavar only to long flag if both short and long
                    # are specified. This won't affect the usage message
                    #
                    # -f, --foo <FOO>
                    # -f <FOO>
                    # --foo <FOO>
                    if (option_string[:2] == "--"
                            # no long flag present, add metavar to short
                            or (option_string[:2] != "--"
                                and len(action.option_strings) == 1)):
                        parts.append(f"{option_string} {args_string}")
                    else:
                        parts.append(f"{option_string}")

            return ", ".join(parts)

    @override
    def _metavar_formatter(
            self,
            action: argparse.Action,
            default_metavar: str,
    ) -> Callable[[int], tuple[str, ...]]:
        if action.metavar is not None:
            result = action.metavar
        elif action.choices is not None:
            choices_iter = iter(action.choices)
            first = last = next(choices_iter)

            for choice in choices_iter:
                last = choice

            result = f"<{str(first)}..{str(last)}>"
        else:
            result = default_metavar

        def format(tuple_size: int) -> tuple[str, ...]:
            if isinstance(result, tuple):
                return result
            else:
                return (result, ) * tuple_size

        return format

    @override
    def _fill_text(self, text: str, width: int, indent: str) -> str:
        if "\n" not in text:
            return super()._fill_text(text, width, indent)
        else:
            return argparse.RawDescriptionHelpFormatter._fill_text(
                self, text, width, indent)


class FlagParser(argparse.ArgumentParser):
    """
    Command line argument parser.
    """

    def __init__(
            self,
            prog: str | None = None,
            usage: str | None = None,
            description: str | None = None,
            epilog: str | None = None,
            parents: Sequence[argparse.ArgumentParser] | None = None,
            formatter_class: type[argparse.HelpFormatter] = FlagHelpFormatter,
            prefix_chars: str = "-",
            fromfile_prefix_chars: str | None = None,
            argument_default: Any | None = None,
            conflict_handler: str = "error",
            add_help: bool = True,
            allow_abbrev: bool = True,
            exit_on_error: bool = True,
    ) -> None:
        if parents is None:
            parents = []
        super().__init__(prog, usage, description, epilog, parents,
                         formatter_class, prefix_chars, fromfile_prefix_chars,
                         argument_default, conflict_handler, add_help,
                         allow_abbrev, exit_on_error)

    def add_arguments(
            self,
            arguments: dict[str, PositionalFlag | OptionFlag | Group],
            *,
            _add_argument_callback: Any | None = None,
    ) -> None:
        """
        This function lacks documentation.

        :param arguments:
            pass

        :param _add_argument_callback:
            This parameter is considered an implementation detail.
            Do not use it when calling this function.
        """
        if _add_argument_callback is None:
            add = self.add_argument
        else:
            add = _add_argument_callback
        for dest, flag in arguments.items():
            try:
                if isinstance(flag, Group):
                    # no arguments, no description, nothing to add
                    if len(flag.arguments) == 0 and flag.description is None:
                        continue
                    elif len(flag.arguments) == 0 and flag.description is not None:
                        self.add_argument_group(dest, flag.description)
                        continue

                    group = self.add_argument_group(dest, flag.description)
                    self.add_arguments(
                        flag.arguments,
                        _add_argument_callback=group.add_argument)
                else:
                    if isinstance(flag, PositionalFlag):
                        add(dest, nargs=flag.nargs, type=flag.type,
                            help=flag.help, default=flag.default)
                    else:
                        # since it's possible to None the flags, throw the exception in
                        # that case
                        if flag.short is None and flag.long is None:
                            raise ValueError("neither short nor long flag was supplied")

                        flags = []

                        if flag.short is not None:
                            flags.append(flag.short)

                        if flag.long is not None:
                            flags.append(flag.long)

                        kwargs = {
                            "action": flag.action,
                            "nargs": flag.nargs,
                            "const": flag.const,
                            "type": flag.type,
                            "required": flag.required,
                            "default": flag.default,
                            "choices": flag.choices,
                            "help": flag.help,
                            "metavar": flag.metavar,
                            "dest": dest,
                            "version": flag.version,
                        }

                        kwargs = {k: v for k, v in kwargs.items() if v is not None}
                        add(*flags, **kwargs)
            except argparse.ArgumentError as e:
                self.error(e.message)

    @override
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        args = {
            "precedence": f"{Color.red(Color.bold('error'))}: "
                          f"{Color.red(Color.bold(self.prog))}",
            "message": message,
        }
        self.exit(2, "%(precedence)s: %(message)s" % args)
