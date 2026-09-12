import assert from "node:assert/strict";
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const { createGraphBrowser, validateHistoryCatalog } = await import(pathToFileURL(process.argv[2]));
const fixture = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
class Element {
  constructor(tag = "div") { this.tagName = tag.toUpperCase(); this.children = []; this.listeners = new Map(); this.value = ""; this.textContent = ""; this.disabled = false; this.hidden = false; this.attributes = new Map(); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener(type, handler) { this.listeners.set(type, handler); }
  setAttribute(key, value) { this.attributes.set(key, value); }
  querySelectorAll(tag) { return this.children.flatMap((child) => [...(child.tagName === tag.toUpperCase() ? [child] : []), ...child.querySelectorAll(tag)]); }
  focus() { this.focused = true; }
  async fire(type) { if (type === "click" && this.disabled) return; await this.listeners.get(type)?.({ preventDefault() {} }); }
}
const elements = new Map();
const element = (name) => { const id = `#graph-browser-${name}`; if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
const document = { querySelector: (id) => element(id.replace("#graph-browser-", "")), createElement: (tag) => new Element(tag) };
const requests = [];
let connected = true, epoch = 1;
const panel = createGraphBrowser({ document, isOperator: () => connected, authEpoch: () => epoch, request: (url) => new Promise((resolve, reject) => requests.push({ url, resolve, reject })) });
const flush = () => new Promise(setImmediate);
const refresh = element("refresh").fire("click");
requests.shift().resolve(fixture.campaigns); await refresh;
assert.equal(element("campaign").children.length, 3);
element("campaign").value = fixture.first.campaignId;
await element("campaign").fire("change");
const old = requests.shift();
element("campaign").value = fixture.second.campaignId;
await element("campaign").fire("change");
const recent = requests.shift(); recent.resolve(fixture.second); await flush();
const currentText = element("status").textContent;
old.resolve(fixture.first); await flush();
assert.equal(element("status").textContent, currentText);
assert.equal(element("list").children.length, fixture.second.items.length);
assert.equal(element("panel").attributes.get("aria-busy"), "false");
element("campaign").value = fixture.first.campaignId;
await element("campaign").fire("change"); requests.shift().resolve(fixture.first); await flush();
const button = element("list").children[0].children[0];
const click = button.fire("click");
await button.fire("click"); assert.equal(requests.length, 1, "busy state must deduplicate");
requests.shift().resolve(fixture.page); await click;
assert.equal(element("result").hidden, false);
assert.match(element("summary").textContent, /Historical read/);
const reload = element("reload").fire("click");
requests.shift().reject(new Error("offline")); await reload; await flush();
assert.match(element("status").textContent, /offline/);
assert.equal(element("result").hidden, true);
assert.equal(element("reload").disabled, false);
const delayed = element("reload").fire("click");
const inflight = requests.shift(); connected = false; epoch += 1; panel.clear();
inflight.resolve(fixture.first); await delayed; await flush();
assert.equal(element("list").children.length, 0);
assert.equal(element("result").hidden, true);
assert.equal(element("refresh").disabled, true);
assert.throws(() => validateHistoryCatalog({ ...fixture.first, historicalReadOnly: false }, fixture.first.campaignId));
assert.throws(() => validateHistoryCatalog(fixture.first, fixture.second.campaignId));
assert.throws(() => validateHistoryCatalog({ ...fixture.first, total: fixture.first.total + 1 }, fixture.first.campaignId));
console.log("Graph browser: reordered responses, duplicate click, offline, reload, auth reset and protocol refusal passed");
