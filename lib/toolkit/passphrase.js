"use strict";
// Diceware-style memorable passphrase generator. Distinct from genpass (random
// chars): picks whole words from an embedded list, which is far easier to recall
// and — with enough words — just as strong. Selection uses crypto.randomInt by
// default, but the rng is INJECTABLE so tests are deterministic. Pure otherwise.
const crypto = require("crypto");

// 256 short, common, unambiguous words (no leetable/confusable pairs). log2(256)=8
// bits of entropy per word: 4 words ~= 32 bits, 6 words ~= 48 bits.
const WORDS = [
  "able", "acid", "acorn", "actor", "agent", "air", "alarm", "album", "alert", "alien",
  "alley", "amber", "angle", "ankle", "apple", "april", "apron", "arena", "armor", "arrow",
  "ash", "aspen", "atlas", "atom", "aunt", "autumn", "axis", "bacon", "badge", "bagel",
  "baker", "balloon", "bamboo", "banjo", "barn", "basil", "basin", "batch", "beach", "beacon",
  "beam", "bean", "bear", "beaver", "bench", "berry", "birch", "bird", "bison", "blade",
  "blaze", "bloom", "board", "boat", "bolt", "bonus", "boot", "boulder", "brave", "bread",
  "brick", "bridge", "brook", "broom", "brush", "bubble", "buffalo", "bugle", "bunny", "cabin",
  "cable", "cactus", "camel", "candle", "canoe", "canyon", "cargo", "carpet", "carrot", "castle",
  "cattle", "cedar", "cello", "chalk", "cherry", "chess", "chime", "clay", "cliff", "cloud",
  "clover", "coal", "cobra", "cocoa", "comet", "coral", "cotton", "cougar", "coyote", "crane",
  "crate", "crayon", "creek", "cricket", "crown", "crystal", "cube", "cavern", "daisy", "dance",
  "dawn", "deer", "delta", "denim", "desert", "diamond", "diner", "dolphin", "domino", "donkey",
  "dove", "dragon", "drum", "dune", "eagle", "earth", "easel", "echo", "eclipse", "elbow",
  "elder", "elk", "ember", "emerald", "engine", "ermine", "fable", "falcon", "fawn", "feather",
  "fennel", "fern", "ferry", "fiber", "fig", "finch", "fjord", "flame", "flint", "flock",
  "flower", "flute", "forest", "fossil", "fox", "frost", "galaxy", "garden", "gecko", "ginger",
  "glacier", "glade", "glider", "globe", "gopher", "granite", "grape", "grove", "guitar", "hammer",
  "harbor", "harvest", "hawk", "hazel", "heron", "hickory", "honey", "hornet", "horse", "ivory",
  "ivy", "jacket", "jaguar", "jasmine", "jelly", "jungle", "kayak", "kettle", "kitten", "koala",
  "lagoon", "lantern", "lark", "laurel", "lemon", "leopard", "lilac", "lily", "linen", "lizard",
  "llama", "lobster", "locket", "lotus", "lumber", "lynx", "magnet", "mango", "maple", "marble",
  "meadow", "melon", "meteor", "mint", "moose", "moss", "moth", "muffin", "mushroom", "napkin",
  "nectar", "needle", "nickel", "noodle", "oasis", "ocean", "olive", "onyx", "opal", "orbit",
  "orchid", "otter", "owl", "oyster", "paddle", "panda", "pansy", "parrot", "peach", "pearl",
  "pebble", "pelican", "pepper", "petal", "pigeon", "pillow", "pine", "planet", "plum", "pony",
  "poppy", "prairie", "puma", "pumpkin", "quartz", "quilt", "rabbit", "radish",
];

// genPassphrase(n, rng?) — n words joined by "-". rng(max) must return an integer
// in [0, max). Defaults to crypto.randomInt (uniform, unbiased). Injectable for tests.
function genPassphrase(n, rng) {
  const count = Number.isInteger(n) && n > 0 ? Math.min(n, 32) : 4;
  const pick = typeof rng === "function" ? rng : (max) => crypto.randomInt(max);
  const out = [];
  for (let i = 0; i < count; i++) out.push(WORDS[pick(WORDS.length)]);
  return out.join("-");
}

// bits of entropy for an n-word phrase from this list
function passphraseBits(n) {
  const count = Number.isInteger(n) && n > 0 ? Math.min(n, 32) : 4;
  return Math.round(count * Math.log2(WORDS.length));
}

module.exports = { WORDS, genPassphrase, passphraseBits };
