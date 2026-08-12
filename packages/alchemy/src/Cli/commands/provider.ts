import * as Console from "effect/Console";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import { Command, Flag } from "effect/unstable/cli";

import {
  describeEnvironment,
  type AuthProvider,
  type EnvironmentVariable,
} from "../../Auth/AuthProvider.ts";
import { getEnv } from "../../Auth/Env.ts";
import { loadConfigProvider } from "../../Util/ConfigProvider.ts";
import { resolveProfileName } from "../ProfileSelection.ts";
import { CliKit } from "../CliKit/CliKit.ts";
import { collectAuthProviders } from "./profile/flows.ts";

import { awsCommand } from "./aws.ts";
import { cloudflareCommand } from "./cloudflare.ts";
import {
  buildStackProviders,
  config,
  envFile,
  instrumentCommand,
  UserInputError,
} from "./_shared.ts";

const providerFilter = Flag.string("provider").pipe(
  Flag.withDescription(
    "Check only this provider (repeatable; defaults to every provider the stack registers)",
  ),
  Flag.atLeast(0),
);

/**
 * `true` when the variable's requirement is satisfied: its name or any
 * declared alternative resolves to a non-empty value.
 */
const isSatisfied = (variable: EnvironmentVariable) =>
  Effect.gen(function* () {
    for (const name of [variable.name, ...(variable.alternatives ?? [])]) {
      const value = yield* getEnv(name);
      if (value !== undefined && value.length > 0) return true;
    }
    return false;
  });

const listCommand = Command.make(
  "list",
  { main: config, envFile },
  instrumentCommand("provider.list")(
    Effect.fn(function* ({ main, envFile }) {
      const profile = yield* resolveProfileName(envFile, undefined);
      const registry = yield* collectAuthProviders({ main, envFile, profile });
      const names = Object.keys(registry).sort();
      for (const name of names) {
        const provider: AuthProvider = registry[name]!;
        const env =
          provider.environment.length === 0
            ? "no CI environment contract"
            : describeEnvironment(provider.environment);
        const methods =
          provider.configureMethods === undefined
            ? "interactive only"
            : `--method ${provider.configureMethods.map((m) => m.method).join(" | ")}`;
        yield* Console.log(`${name}\n  env: ${env}\n  configure: ${methods}`);
      }
    }),
  ),
).pipe(
  Command.withDescription(
    "List registered auth providers, their CI environment contracts, and flag-driven configure methods",
  ),
);

const checkEnvCommand = Command.make(
  "check-env",
  { provider: providerFilter, main: config, envFile },
  instrumentCommand("provider.check-env")(
    Effect.fn(function* ({ provider: requested, main, envFile }) {
      const cli = yield* CliKit;
      // The stack's own providers() registrations define "what this project
      // uses" — the built-in registry would flag providers the project never
      // touches. Outside a project, an explicit --provider list is required.
      const fs = yield* FileSystem.FileSystem;
      const hasEntrypoint = yield* fs.exists(main);
      let registry: Record<string, AuthProvider>;
      if (hasEntrypoint && requested.length === 0) {
        const { authProviders } = yield* buildStackProviders({
          main,
          envFile,
          profile: yield* resolveProfileName(envFile, undefined),
        });
        registry = authProviders;
      } else if (requested.length > 0) {
        const profile = yield* resolveProfileName(envFile, undefined);
        const all = yield* collectAuthProviders({ main, envFile, profile });
        registry = {};
        for (const input of requested) {
          const name = Object.keys(all).find(
            (candidate) => candidate.toLowerCase() === input.toLowerCase(),
          );
          if (name === undefined) {
            return yield* Effect.fail(
              new UserInputError({
                message: `Unknown provider '${input}'. Registered: ${Object.keys(all).sort().join(", ")}.`,
              }),
            );
          }
          registry[name] = all[name]!;
        }
      } else {
        return yield* Effect.fail(
          new UserInputError({
            message: `No stack entrypoint at '${main}'. Run inside an Alchemy project (or pass --config), or name providers explicitly with --provider.`,
          }),
        );
      }

      // Resolve variables against the process env merged with --env-file,
      // exactly as credential resolution would see them.
      const configProvider = yield* loadConfigProvider(envFile);
      yield* Effect.gen(function* () {
        const names = Object.keys(registry).sort();
        let failed = false;
        for (const name of names) {
          const environment = registry[name]!.environment;
          if (environment.length === 0) {
            yield* cli.output.info({
              message: name,
              detail: "No CI environment contract",
            });
            continue;
          }
          const missing: string[] = [];
          for (const variable of environment) {
            if (variable.required && !(yield* isSatisfied(variable))) {
              missing.push(
                [variable.name, ...(variable.alternatives ?? [])].join(" | "),
              );
            }
          }
          if (missing.length === 0) {
            yield* cli.output.success(name);
          } else {
            failed = true;
            yield* cli.output.error({
              message: name,
              detail: `Missing: ${missing.join(", ")}`,
            });
          }
        }
        if (failed) {
          yield* cli.output.info(
            "Set the missing variables; run `alchemy provider list` for each provider's full contract.",
          );
          yield* Effect.sync(() => {
            process.exitCode = 1;
          });
        }
      }).pipe(Effect.provide(ConfigProvider.layer(configProvider)));
    }),
  ),
).pipe(
  Command.withDescription(
    "Verify the required environment variables for the stack's providers are set (CI preflight; exits 1 when any are missing)",
  ),
);

export const providerCommand = Command.make("provider", {}).pipe(
  Command.withDescription("Manage cloud provider prerequisites and utilities"),
  Command.withSubcommands([
    listCommand,
    checkEnvCommand,
    awsCommand,
    cloudflareCommand,
  ]),
);
