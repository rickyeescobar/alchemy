import { plainCliFormatter } from "@/Cli/PlainCliFormatter.ts";
import * as Context from "effect/Context";
import * as Option from "effect/Option";
import { expect, it } from "alchemy-test";

it("separates sections and bounds long flag rows", () => {
  const output = plainCliFormatter({ columns: 80 }).formatHelpDoc({
    description:
      "Define, deploy, and operate cloud infrastructure with type-safe Effect programs.",
    usage: "alchemy <subcommand> [flags]",
    annotations: Context.empty(),
    flags: [],
    globalFlags: [
      {
        name: "log-level",
        aliases: [],
        type: "all|trace|debug|info|warn|warning|error|fatal|none",
        description: Option.some(
          "Sets the minimum log level for every command and provider.",
        ),
        required: false,
      },
    ],
    subcommands: [
      {
        group: undefined,
        commands: [
          {
            name: "deploy",
            alias: undefined,
            shortDescription: "Deploy a stack",
            description: "Deploy a stack",
          },
        ],
      },
    ],
    examples: [{ command: "alchemy deploy" }],
  });

  expect(output).toContain("\n\nUSAGE\n");
  expect(output).toContain("\n\nCOMMANDS\n");
  expect(output).toContain("\n\nGLOBAL FLAGS\n");
  expect(output).toContain("\n\nEXAMPLES\n");
  expect(output).toContain("--log-level <all|trace|…>");
  for (const line of output.split("\n")) {
    expect(line.length <= 80).toBe(true);
  }
});
