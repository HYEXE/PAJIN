import assert from "node:assert/strict";
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const { createMeasuredReviews, validateMeasuredReview } = await import(pathToFileURL(process.argv[2]));
const fixture = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
let focused = null;
class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.listeners = new Map();
    this.value = ""; this.textContent = ""; this.disabled = false; this.hidden = false;
    this.attributes = new Map(); this.dataset = {};
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener(type, handler) { this.listeners.set(type, handler); }
  setAttribute(key, value) { this.attributes.set(key, String(value)); }
  querySelectorAll(selector) {
    const tags = selector.split(",").map((tag) => tag.trim().toUpperCase());
    return this.children.flatMap((child) => [...(tags.includes(child.tagName) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  reset() { this.querySelectorAll("input, select, textarea").forEach((field) => { field.value = ""; }); }
  focus() { focused = this; }
  async fire(type) { if (type === "click" && this.disabled) return; await this.listeners.get(type)?.({ preventDefault() {} }); }
}
const elements = new Map();
const element = (name, tag) => {
  if (!elements.has(name)) elements.set(name, new Element(tag));
  return elements.get(name);
};
element("assignment-form", "form").append(element("assignee", "select"), element("assignment-reason", "textarea"), element("assign", "button"));
const document = { querySelector: (id) => element(id.replace("#measured-review-", "")), createElement: (tag) => new Element(tag) };
const requests = [], announcements = [];
let epoch = 1;
let role = { connected: true, operator: true, approver: false, subject: "web-operator" };
const panel = createMeasuredReviews({
  document, authEpoch: () => epoch, access: () => role,
  request: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  requestReport: () => { throw new Error("Assignment must not request a report"); },
  announce: (...args) => announcements.push(args),
});
const flush = () => new Promise(setImmediate);
const respond = async (value) => { assert.ok(requests.length); requests.shift().resolve(value); await flush(); };
element("lookup-id").value = fixture.opened.reviewId;
await element("lookup-form").fire("submit"); await respond(fixture.opened);
const roster = element("assignee-refresh").fire("click");
await respond(["web-approver", "web-operator"]); await roster;
assert.equal(element("assign").disabled, false);
element("assignee").value = "web-approver";
element("assignment-reason").value = "Please review this evidence.";
await element("assignment-form").fire("submit");
await element("assignment-form").fire("submit");
assert.equal(requests.length, 1, "busy assignment must not duplicate the write");
const failed = requests.shift();
const firstBody = JSON.parse(failed.options.body);
failed.reject(new Error("offline")); await flush();
assert.match(element("status").textContent, /offline/);
assert.equal(element("assignment-reason").value, "Please review this evidence.");
assert.equal(element("assignee").value, "web-approver");
assert.equal(element("assign").disabled, false);
await element("assignment-form").fire("submit");
assert.deepEqual(JSON.parse(requests[0].options.body), firstBody, "retry preserves the exact intent and key");
await respond(fixture.assigned);
assert.equal(requests[0].url, `/v1/measured-reviews/${fixture.opened.reviewId}`);
await respond(fixture.assigned);
assert.match(element("detail").children.map((child) => child.textContent).join(" "), /web-approver/);
assert.equal(element("panel").attributes.get("aria-busy"), "false");

role = { connected: true, operator: false, approver: true, subject: "web-approver" }; epoch += 1;
panel.clear();
const inbox = element("inbox-refresh").fire("click");
await respond(fixture.unread); await inbox;
const mark = element("inbox").querySelectorAll("button").find((button) => button.textContent === "Mark read");
assert.ok(mark);
mark.focus();
const marking = mark.fire("click");
await mark.fire("click"); assert.equal(requests.length, 1);
await respond(fixture.assigned);
assert.match(requests[0].url, /\/notification-ack$/);
assert.equal(JSON.parse(requests[0].options.body).assignmentRevision, 2);
await respond(fixture.acked);
await respond(fixture.acked);
assert.equal(requests[0].url, "/v1/measured-review-inbox");
await respond(fixture.read); await marking;
assert.match(element("inbox").children[0].children[0].textContent, /^Read/);
assert.equal(element("inbox").querySelectorAll("button").length, 1);
assert.equal(focused, element("inbox-status"), "replacement of the read button must retain keyboard focus");
assert.equal(element("assign").disabled, true, "assignment never grants operator permission");

role = { connected: true, operator: false, approver: false, subject: "web-approver" }; epoch += 1;
panel.clear();
const readingOnly = element("inbox-refresh").fire("click");
await respond(fixture.unread); await readingOnly;
assert.equal(element("inbox").querySelectorAll("button").length, 1);
assert.match(element("inbox").children[0].children.at(-1).textContent, /reading this notification only/);

role = { connected: true, operator: false, approver: true, subject: "web-approver" }; epoch += 1;
panel.clear();
const full = structuredClone(fixture.unread);
full.items[0].assignmentRevision = full.items[0].currentRevision = 200;
const atCapacity = element("inbox-refresh").fire("click");
await respond(full); await atCapacity;
assert.equal(element("inbox").querySelectorAll("button").length, 1);
assert.match(element("inbox").children[0].children.at(-1).textContent, /history is full/);

const delayed = element("inbox-refresh").fire("click");
role = { connected: false, operator: false, approver: false, subject: "" }; epoch += 1;
panel.clear();
await respond(fixture.unread); await delayed;
assert.equal(element("inbox").children.length, 0);
assert.equal(element("workspace").hidden, true);
assert.equal(element("inbox-refresh").disabled, true);
assert.equal(element("assignment-reason").value, "");
assert.throws(() => validateMeasuredReview({ ...fixture.assigned, apiVersion: "pajin.dev/measured-human-review/v1" }));
assert.throws(() => validateMeasuredReview({ ...fixture.assigned, executionAuthorized: true }));
assert.equal(announcements.filter(([, state]) => state === "error").length, 1);
assert.equal(requests.length, 0);
console.log("Review assignments: duplicate write, exact retry, preserved input, personal acknowledgment, focus, role boundary and auth reset passed");
