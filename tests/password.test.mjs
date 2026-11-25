import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzePassword,
  estimateEntropy,
  generatePassword,
  generatePassphrase,
  findSequences,
  findKeyboardWalks,
  isCommonPassword,
} from "../app.js";

test("weak password 'password123' scores low and is flagged common", () => {
  const result = analyzePassword("password123");
  assert.equal(result.isCommon, true);
  assert.ok(result.score <= 1, `expected low score, got ${result.score}`);
  assert.ok(result.entropy < 35, `expected low entropy, got ${result.entropy}`);
  assert.ok(result.findings.some((f) => f.type === "common"));
});

test("leetspeak variant of a common password is flagged", () => {
  assert.equal(isCommonPassword("p@ssw0rd"), true);
  assert.equal(analyzePassword("P@ssw0rd!").isCommon, true);
});

test("strong random password scores high", () => {
  const strong = "X9$kQ2!mZ7#pL4&vR8@nW3";
  const result = analyzePassword(strong);
  assert.ok(result.score >= 3, `expected high score, got ${result.score}`);
  assert.ok(result.entropy >= 80, `expected high entropy, got ${result.entropy}`);
  assert.equal(result.isCommon, false);
});

test("entropy grows with length and charset variety", () => {
  assert.ok(estimateEntropy("abcdefgh") < estimateEntropy("aB3$xY9!qW7#zK2&"));
  assert.equal(estimateEntropy(""), 0);
});

test("sequence detection finds abc / 123 runs", () => {
  const seqs = findSequences("xyzabc123");
  assert.ok(seqs.length >= 1);
  assert.ok(seqs.some((s) => s.includes("abc") || s.includes("123")));
  const result = analyzePassword("abc12345");
  assert.ok(result.sequences.length >= 1);
  assert.ok(result.findings.some((f) => f.type === "sequence"));
});

test("keyboard walk detection finds qwerty runs", () => {
  const walks = findKeyboardWalks("qwerty99");
  assert.ok(walks.length >= 1);
  assert.ok(walks.some((w) => "qwerty".includes(w) || w.includes("qwert")));
});

test("year / date patterns are flagged", () => {
  const result = analyzePassword("Dragon2024!");
  assert.equal(result.hasYearOrDate, true);
  assert.ok(result.findings.some((f) => f.type === "date"));
});

test("generator respects length", () => {
  for (const len of [8, 16, 24, 40]) {
    assert.equal(generatePassword({ length: len }).length, len);
  }
});

test("generator respects charset selection", () => {
  const digitsOnly = generatePassword({ length: 20, lowercase: false, uppercase: false, digits: true, symbols: false });
  assert.match(digitsOnly, /^[0-9]+$/);

  const lowerOnly = generatePassword({ length: 20, lowercase: true, uppercase: false, digits: false, symbols: false });
  assert.match(lowerOnly, /^[a-z]+$/);

  const noSymbols = generatePassword({ length: 24, symbols: false });
  assert.doesNotMatch(noSymbols, /[^A-Za-z0-9]/);
});

test("generator includes each selected class when length allows", () => {
  const pw = generatePassword({ length: 20 });
  assert.match(pw, /[a-z]/);
  assert.match(pw, /[A-Z]/);
  assert.match(pw, /[0-9]/);
  assert.match(pw, /[^A-Za-z0-9]/);
});

test("generator exclude-ambiguous removes Il1O0", () => {
  for (let i = 0; i < 25; i++) {
    const pw = generatePassword({ length: 32, excludeAmbiguous: true });
    assert.doesNotMatch(pw, /[Il1O0]/);
  }
});

test("generator rejects an empty charset selection", () => {
  assert.throws(() => generatePassword({ lowercase: false, uppercase: false, digits: false, symbols: false }));
});

test("passphrase respects word count and separator", () => {
  const phrase = generatePassphrase({ wordCount: 5, separator: "-" });
  assert.equal(phrase.split("-").length, 5);

  const underscored = generatePassphrase({ wordCount: 3, separator: "_" });
  assert.equal(underscored.split("_").length, 3);
});

test("passphrase capitalize and number options", () => {
  const phrase = generatePassphrase({ wordCount: 4, separator: "-", capitalize: true, includeNumber: true });
  const parts = phrase.split("-");
  assert.equal(parts.length, 4);
  for (const part of parts.slice(0, 3)) assert.match(part, /^[A-Z][a-z]+$/);
  assert.match(parts[3], /^[A-Z][a-z]+[0-9]$/);
});

test("generated passwords analyze as stronger than common ones", () => {
  const generated = generatePassword({ length: 20 });
  assert.ok(analyzePassword(generated).entropy > analyzePassword("password123").entropy);
});
