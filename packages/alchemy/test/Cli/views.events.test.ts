import { makeEventHub } from "@/Cli/views/events.ts";
import { expect, it } from "alchemy-test";

it("buffers live events until the view mounts without replaying twice", () => {
  const hub = makeEventHub<number>();
  hub.emit(1);

  const first: number[] = [];
  const unsubscribe = hub.source.subscribe((event) => first.push(event));
  expect(first).toEqual([1]);
  unsubscribe();

  const second: number[] = [];
  hub.source.subscribe((event) => second.push(event));
  expect(second).toEqual([]);
  hub.emit(2);
  expect(second).toEqual([2]);
});
