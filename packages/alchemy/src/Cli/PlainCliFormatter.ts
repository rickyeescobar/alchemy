import * as Option from "effect/Option";
import * as CliOutput from "effect/unstable/cli/CliOutput";
import type {
  ArgDoc,
  FlagDoc,
  HelpDoc,
  SubcommandDoc,
} from "effect/unstable/cli/HelpDoc";

const wrap = (text: string, width: number): ReadonlyArray<string> => {
  if (text === "") return [""];
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line === "") {
      line = word;
    } else if (line.length + word.length + 1 <= width) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line !== "") lines.push(line);
  return lines;
};

const compactType = (type: string): string => {
  const value = type.replace(/^<|>$/g, "");
  if (value.length <= 22) return value;
  const choices = value.split("|");
  if (choices.length > 2) return `${choices.slice(0, 2).join("|")}|…`;
  return `${value.slice(0, 21)}…`;
};

const flagLabel = (flag: FlagDoc): string => {
  const aliases =
    flag.aliases.length === 0 ? "" : `, ${flag.aliases.join(", ")}`;
  const type = flag.type === "boolean" ? "" : ` <${compactType(flag.type)}>`;
  return `--${flag.name}${aliases}${type}`;
};

const argLabel = (arg: ArgDoc): string => {
  const name = `${arg.name}${arg.variadic ? "…" : ""}`;
  return arg.required ? `<${name}>` : `[${name}]`;
};

const commandLabel = (command: SubcommandDoc): string =>
  command.alias === undefined
    ? command.name
    : `${command.name}, ${command.alias}`;

const rows = (
  values: ReadonlyArray<readonly [label: string, description: string]>,
  columns: number,
): ReadonlyArray<string> => {
  if (values.length === 0) return [];
  const labelWidth = Math.min(
    30,
    Math.max(12, ...values.map(([label]) => label.length)),
  );
  const descriptionWidth = Math.max(24, columns - labelWidth - 4);
  return values.flatMap(([label, description]) => {
    const wrapped = wrap(description, descriptionWidth);
    if (label.length > labelWidth) {
      return [`  ${label}`, ...wrapped.map((line) => `    ${line}`.trimEnd())];
    }
    return wrapped.map((line, index) =>
      index === 0
        ? `  ${label.padEnd(labelWidth)}  ${line}`.trimEnd()
        : `${" ".repeat(labelWidth + 4)}${line}`.trimEnd(),
    );
  });
};

const section = (
  title: string,
  lines: ReadonlyArray<string>,
): ReadonlyArray<string> => (lines.length === 0 ? [] : [title, ...lines]);

const formatHelp = (doc: HelpDoc, columns: number): string => {
  const sections: ReadonlyArray<ReadonlyArray<string>> = [
    doc.description === ""
      ? []
      : section(
          "DESCRIPTION",
          wrap(doc.description, columns - 2).map((line) => `  ${line}`),
        ),
    section("USAGE", [`  ${doc.usage}`]),
    section(
      "ARGUMENTS",
      rows(
        (doc.args ?? []).map((arg) => [
          argLabel(arg),
          Option.getOrElse(arg.description, () => ""),
        ]),
        columns,
      ),
    ),
    section(
      "COMMANDS",
      rows(
        (doc.subcommands?.flatMap((group) => group.commands) ?? []).map(
          (command) => [
            commandLabel(command),
            command.shortDescription || command.description || "",
          ],
        ),
        columns,
      ),
    ),
    section(
      "FLAGS",
      rows(
        doc.flags.map((flag) => [
          flagLabel(flag),
          Option.getOrElse(flag.description, () => ""),
        ]),
        columns,
      ),
    ),
    section(
      "GLOBAL FLAGS",
      rows(
        (doc.globalFlags ?? []).map((flag) => [
          flagLabel(flag),
          Option.getOrElse(flag.description, () => ""),
        ]),
        columns,
      ),
    ),
    section(
      "EXAMPLES",
      (doc.examples ?? []).flatMap((example) => [
        `  ${example.command}`,
        ...(example.description === undefined
          ? []
          : wrap(example.description, columns - 4).map(
              (line) => `    ${line}`,
            )),
      ]),
    ),
  ];

  return sections
    .filter((lines) => lines.length > 0)
    .map((lines) => lines.join("\n"))
    .join("\n\n");
};

/** Plain formatter for CI, redirected output and coding agents. */
export const plainCliFormatter = (
  options: {
    readonly columns?: number;
  } = {},
): CliOutput.Formatter => {
  const columns = Math.max(60, Math.min(options.columns ?? 80, 120));
  const fallback = CliOutput.defaultFormatter({ colors: false });
  return {
    ...fallback,
    formatHelpDoc: (doc) => formatHelp(doc, columns),
    formatVersion: (name, version) => `${name} v${version}`,
    formatError: (error) => `\nError: ${error.message}`,
    formatErrors: (errors) =>
      errors.length === 0
        ? ""
        : `\n${errors.map((error) => `Error: ${error.message}`).join("\n")}`,
  };
};
