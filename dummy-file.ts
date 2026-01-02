const Anthropic = require('@anthropic-ai/sdk');

//  Anthropic key following the sk-ant-api03 format
const ANTHROPIC_KEY = "sk-ant-api03-X7y_z2W1p9V8q7R6s5T4u3N2m1L0k9J8i7H6g5F4e3D2c1B0a9Z8y7X6w5V4u3T2s1R0q9P8o7N6m5L4k3J2i1H0g9F8e7D6";

const client = new Anthropic({
  apiKey: ANTHROPIC_KEY,
});

console.log("Anthropic client initialized.");